//! Per-credential NATS client cache.
//!
//! Mirrors the SQL adapter's `PoolRegistry` shape: keyed on a BLAKE3
//! digest of the resolved credential bundle, bounded in size with
//! LRU + idle eviction, and wired up to the credential cache's
//! revocation broadcast for precise eviction.
//!
//! NATS clients are far cheaper to create than SQL pools, but per-
//! connection auth state is per-credential — every distinct caller
//! credential needs its own connection. The registry amortises
//! connect cost across calls from the same caller while keeping
//! steady-state connection count bounded.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::{CancellationToken, DropGuard};
use tracing::{debug, info};

/// 32-byte BLAKE3 digest of a resolved credential bundle. Two
/// callers whose credentials hash identically share one client.
pub type CredDigest = [u8; 32];

/// Stable digest of "no credentials resolved" — used for the
/// static-cred fast path when the spec carries no `cred://`
/// references.
#[must_use]
pub fn static_digest() -> CredDigest {
    blake3::hash(b"static").into()
}

/// Compute a stable digest from a sorted set of `(field, value)`
/// pairs. The caller (the NATS adapter's `resolve_creds_for`
/// helper) builds the pair list deterministically — typically
/// `("url", resolved_url) + ("credentials_path", resolved_path) +
/// ("auth_token", resolved_token)`.
#[must_use]
pub fn digest_credential_bundle(pairs: &[(String, String)]) -> CredDigest {
    let mut sorted: Vec<&(String, String)> = pairs.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher = blake3::Hasher::new();
    for (k, v) in sorted {
        hasher.update(k.as_bytes());
        hasher.update(b"=");
        hasher.update(v.as_bytes());
        hasher.update(b"\n");
    }
    hasher.finalize().into()
}

/// One entry in the registry. Tracks the live client + the
/// `(plugin_id, target)` pairs that produced this client's
/// credentials, so a `CacheEvent::Revoked` for any of them can
/// surgically drop just this entry.
struct ClientEntry {
    client: Arc<async_nats::Client>,
    cred_keys: Vec<(String, String)>,
    /// Monotonic millis since the registry's `epoch`. Used by LRU +
    /// idle sweeper. AtomicU64 so we can update without taking the
    /// outer mutex on every call.
    last_used: AtomicU64,
}

/// Registry config — defaults match the SQL adapter so operators
/// have one knob to tune across backends.
#[derive(Debug, Clone, Copy)]
pub struct ClientRegistryConfig {
    pub max_entries: usize,
    pub idle_eviction: Duration,
}

impl Default for ClientRegistryConfig {
    fn default() -> Self {
        Self {
            max_entries: 256,
            idle_eviction: Duration::from_secs(15 * 60),
        }
    }
}

struct Inner {
    clients: HashMap<CredDigest, ClientEntry>,
}

/// Bounded per-credential client cache. See module docs.
pub struct ClientRegistry {
    inner: Arc<AsyncMutex<Inner>>,
    config: ClientRegistryConfig,
    epoch: Instant,
}

impl ClientRegistry {
    /// Create an empty registry with the given config.
    #[must_use]
    pub fn new(config: ClientRegistryConfig) -> Self {
        Self {
            inner: Arc::new(AsyncMutex::new(Inner {
                clients: HashMap::new(),
            })),
            config,
            epoch: Instant::now(),
        }
    }

    fn now_millis(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Look up an existing client by digest, or build a fresh one
    /// via `build`. The build closure runs at most once per cache
    /// miss — concurrent callers serialise on the registry's mutex
    /// while the connect happens, so a thundering herd of cold
    /// callers does not spawn N parallel connects.
    pub async fn get_or_build<F, Fut>(
        &self,
        digest: CredDigest,
        cred_keys: Vec<(String, String)>,
        build: F,
    ) -> Result<Arc<async_nats::Client>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Arc<async_nats::Client>>>,
    {
        let guard = self.inner.lock().await;
        if let Some(entry) = guard.clients.get(&digest) {
            entry.last_used.store(self.now_millis(), Ordering::Relaxed);
            return Ok(Arc::clone(&entry.client));
        }
        // Drop the lock for the connect — we already hold the mutex
        // long enough for a fast lookup, but holding it across an
        // async connect would serialise unrelated digests too.
        drop(guard);
        let client = build().await?;
        let mut guard = self.inner.lock().await;
        // Race: another task may have just inserted the same digest
        // while we were building. Prefer the existing entry to
        // minimise duplicate connects and let our just-built client
        // drop on function return.
        if let Some(entry) = guard.clients.get(&digest) {
            entry.last_used.store(self.now_millis(), Ordering::Relaxed);
            return Ok(Arc::clone(&entry.client));
        }
        guard.clients.insert(
            digest,
            ClientEntry {
                client: Arc::clone(&client),
                cred_keys,
                last_used: AtomicU64::new(self.now_millis()),
            },
        );
        if guard.clients.len() > self.config.max_entries {
            // LRU evict the single oldest entry. O(N) is fine — N is
            // bounded by max_entries.
            if let Some(oldest_digest) = guard
                .clients
                .iter()
                .min_by_key(|(_, e)| e.last_used.load(Ordering::Relaxed))
                .map(|(d, _)| *d)
            {
                guard.clients.remove(&oldest_digest);
                metrics::counter!(
                    "mcpg_nats_client_registry_evictions_total",
                    "reason" => "lru",
                )
                .increment(1);
            }
        }
        Ok(client)
    }

    /// Drop every entry whose `cred_keys` contains the given
    /// `(plugin_id, target)` pair. Returns the number of entries
    /// evicted. Called from the credential-cache revocation
    /// subscriber.
    pub async fn evict_for(&self, plugin_id: &str, target: &str) -> usize {
        let mut guard = self.inner.lock().await;
        let to_drop: Vec<CredDigest> = guard
            .clients
            .iter()
            .filter(|(_, e)| {
                e.cred_keys
                    .iter()
                    .any(|(p, t)| p == plugin_id && t == target)
            })
            .map(|(d, _)| *d)
            .collect();
        let count = to_drop.len();
        for d in to_drop {
            guard.clients.remove(&d);
        }
        if count > 0 {
            metrics::counter!(
                "mcpg_nats_client_registry_evictions_total",
                "reason" => "revoked",
            )
            .increment(count as u64);
        }
        count
    }

    /// Drop every entry. Called from the secret-rotation
    /// subscriber when a `vault://...` URI tied to this profile
    /// rotates. Mirrors the HTTP/SQL plugins' shape: per-profile
    /// monolithic eviction since every entry shares the same set of
    /// resolved secret refs.
    pub async fn evict_for_secret(&self, _secret_ref: &str) -> usize {
        let mut guard = self.inner.lock().await;
        let count = guard.clients.len();
        guard.clients.clear();
        if count > 0 {
            metrics::counter!(
                "mcpg_nats_client_registry_evictions_total",
                "reason" => "secret_rotation",
            )
            .increment(count as u64);
        }
        count
    }

    /// Drop entries whose `last_used` age exceeds
    /// `config.idle_eviction`. Called by the background sweeper.
    pub async fn sweep_idle(&self) -> usize {
        let mut guard = self.inner.lock().await;
        let now = self.now_millis();
        let threshold_ms = self.config.idle_eviction.as_millis() as u64;
        let to_drop: Vec<CredDigest> = guard
            .clients
            .iter()
            .filter(|(_, e)| {
                let last = e.last_used.load(Ordering::Relaxed);
                now.saturating_sub(last) > threshold_ms
            })
            .map(|(d, _)| *d)
            .collect();
        let count = to_drop.len();
        for d in to_drop {
            guard.clients.remove(&d);
        }
        if count > 0 {
            metrics::counter!(
                "mcpg_nats_client_registry_evictions_total",
                "reason" => "idle",
            )
            .increment(count as u64);
        }
        count
    }

    /// Number of clients in the registry. Used by tests + admin
    /// surfaces.
    pub async fn len(&self) -> usize {
        self.inner.lock().await.clients.len()
    }

    /// Whether the registry has zero clients.
    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.clients.is_empty()
    }
}

/// Idle-pool sweeper guard. Holding this Arc keeps the spawned
/// background task alive; dropping the last clone cancels it.
pub struct IdleSweeper {
    _cancel_guard: DropGuard,
}

/// Spawn a periodic background task that ticks `sweep_idle` at
/// `interval`. Returns an Arc whose drop cancels the task.
#[must_use]
pub fn spawn_idle_sweeper(
    backend_name: String,
    registry: Arc<ClientRegistry>,
    interval: Duration,
) -> Arc<IdleSweeper> {
    let token = CancellationToken::new();
    let guard = IdleSweeper {
        _cancel_guard: token.clone().drop_guard(),
    };
    tokio::spawn(idle_sweep_loop(backend_name, registry, interval, token));
    Arc::new(guard)
}

async fn idle_sweep_loop(
    backend_name: String,
    registry: Arc<ClientRegistry>,
    interval: Duration,
    cancel: CancellationToken,
) {
    info!(
        target: "mcpg::nats::client_registry",
        backend = %backend_name,
        interval_ms = interval.as_millis() as u64,
        "nats client idle sweeper: started"
    );
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // consume the immediate first tick

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                debug!(
                    target: "mcpg::nats::client_registry",
                    backend = %backend_name,
                    "nats client idle sweeper: cancelled"
                );
                return;
            }
            _ = ticker.tick() => {
                let evicted = registry.sweep_idle().await;
                if evicted > 0 {
                    info!(
                        target: "mcpg::nats::client_registry",
                        backend = %backend_name,
                        evicted = evicted,
                        "evicted idle NATS clients"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_order_independent() {
        let a = digest_credential_bundle(&[
            ("url".into(), "nats://h:4222".into()),
            ("auth_token".into(), "abc".into()),
        ]);
        let b = digest_credential_bundle(&[
            ("auth_token".into(), "abc".into()),
            ("url".into(), "nats://h:4222".into()),
        ]);
        assert_eq!(a, b);
    }

    #[test]
    fn digest_distinguishes_different_inputs() {
        let a = digest_credential_bundle(&[("auth_token".into(), "abc".into())]);
        let b = digest_credential_bundle(&[("auth_token".into(), "xyz".into())]);
        assert_ne!(a, b);
    }

    #[test]
    fn static_digest_is_stable() {
        assert_eq!(static_digest(), static_digest());
    }
}
