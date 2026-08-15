//! NATS binding plugin for mcpg.
//!
//! Implements:
//!
//! - [`NatsBackendPlugin`] — `BackendPlugin` for `kind: "nats"`, dispatching
//!   tool calls over NATS request/reply. Propagates W3C
//!   `traceparent` / `tracestate` headers when present on the inbound
//!   request.
//!
//! - [`NatsWatchPlugin`] — `WatchStrategyPlugin` for `kind: "nats_topic"`,
//!   spawning a subject subscriber that emits a `WatchEvent` on every
//!   inbound message so resource subscribers receive
//!   `notifications/resources/updated` events.
//!
//! The two plugins share a single `async_nats::Client`, constructed once
//! from a URL + optional credentials file. Create the client via
//! [`connect`] at startup, then wrap the same `Arc<async_nats::Client>`
//! with both plugin types and register them with the host's
//! `PluginRegistry`.

pub mod client_registry;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use futures::StreamExt;
use mcpg_plugin_protocol::credential::{CredRef, cred_tokens, substitute_cred_tokens};
use mcpg_plugin_protocol::redact::redact_url_password;
use mcpg_plugin_protocol::{
    BackendError, BackendPlugin, BackendRequest, BackendResponse, PluginManifest, WatchError,
    WatchEvent, WatchEventSink, WatchHandle, WatchStrategyPlugin, firstparty_manifest,
};
use serde::Deserialize;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, info_span, warn};

use crate::client_registry::{
    CredDigest, IdleSweeper, digest_credential_bundle, spawn_idle_sweeper,
};
use mcpg_plugin_sdk::ffi::{SyncBackendPlugin, SyncWatchStrategyPlugin, WatchHandleBox};
use mcpg_plugin_sdk::{HostHandle, HostHandleBackendHost};

/// Plugin-level config (the `plugins[]` entry's `config:` block,
/// injected by the gateway from the first NATS binding's url +
/// credentials_path). Per-binding subject/timeout arrive via
/// `register_profile`.
///
/// CONSISTENCY INVARIANT (folded in from the gateway's old
/// `validate_nats_binding_consistency`): the gateway used to reject
/// configs where two NATS bindings declared divergent `url` /
/// `credentials_path`, because it opened ONE shared `async_nats::Client`
/// and reused it across every profile — divergent values would silently
/// route half the bindings to the wrong server. Under the generic
/// plugin-agnostic model that cross-binding check is no longer needed:
/// connection params live on the SINGLE `plugins[].config` block (this
/// struct), and one plugin instance is constructed per entry, so there
/// is exactly one connection by construction. The per-binding spec no
/// longer carries connection fields the gateway must reconcile — the
/// invariant is structurally guaranteed rather than validated. (The
/// per-binding spec's optional `url`/`credentials_path` exist only for
/// the per-caller `${cred://…}` credential path, which is intentionally
/// isolated per profile.)
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct NatsPluginConfig {
    #[serde(default)]
    url: String,
    #[serde(default)]
    credentials_path: Option<String>,
}

/// Embedded  descriptor for this plugin.
/// Passed to [`FirstPartyRegistrar::register`] at gateway startup.
pub const BINDING_DESCRIPTOR_YAML: &str = include_str!("../plugin.yaml");

// ---------------------------------------------------------------------------
// Client construction
// ---------------------------------------------------------------------------

/// Connect to a NATS server using the given URL and optional credentials
/// file path. Returns a shared client handle both plugin types can reuse.
pub async fn connect(url: &str, credentials_path: Option<&str>) -> Result<Arc<async_nats::Client>> {
    let options = if let Some(creds) = credentials_path {
        async_nats::ConnectOptions::with_credentials_file(PathBuf::from(creds))
            .await
            .with_context(|| format!("failed to load NATS credentials from {creds}"))?
    } else {
        async_nats::ConnectOptions::new()
    };

    let client = options
        .connect(url)
        .await
        .with_context(|| format!("failed to connect to NATS at {}", redact_url_password(url)))?;

    info!(url = %redact_url_password(url), "mcpg-plugin-backend-nats: connected to NATS");
    Ok(Arc::new(client))
}

// ---------------------------------------------------------------------------
// Backend plugin — request/reply
// ---------------------------------------------------------------------------

/// Spec shape the host serializes when calling `register_profile`.
/// Matches the operator-facing YAML for the `type: nats` backend.
///
/// The optional `url`, `credentials_path`, and `auth_token` fields
/// drive the per-caller credential path: when any carries a
/// `${cred://issuer/target}` token, the plugin resolves it on every
/// call and dispatches the request over a per-credential client
/// maintained in [`client_registry::ClientRegistry`]. When none
/// carry a `${cred://…}` token, the plugin falls back to the
/// constructor-provided shared client.
///
/// Grammar (standardized across backends): a credential resolves
/// ONLY when the operator writes it as a `${cred://issuer/target}`
/// token. A BARE `cred://…` (not wrapped in `${}`) is NOT a
/// credential reference — it travels to NATS verbatim.
// NOTE: NO `#[serde(deny_unknown_fields)]` here. This is the per-binding
// `register_profile` spec, NOT the plugin `config:` block. The gateway
// injects a RESERVED `__mcpg_secret_refs` hint key into this spec object
// post credential-resolution (see `inject_secret_refs_hint` in the gateway
// app; this plugin reads it back at line `spec.get("__mcpg_secret_refs")`
// below to scope rotation eviction). `deny_unknown_fields` would reject
// that injected key and break secret rotation for credentialed NATS
// bindings — this is an intentional forward-compatible passthrough.
#[derive(Debug, Clone, Deserialize)]
struct NatsBackendSpec {
    /// Optional per-binding NATS server URL. Carrying a
    /// `${cred://…}` token here triggers per-caller URL resolution.
    #[serde(default)]
    url: Option<String>,
    /// Optional path to a NATS credentials file. Carrying a
    /// `${cred://…}` token here triggers per-caller file path
    /// resolution (e.g. one credentials file per caller materialised
    /// by a credential issuer).
    #[serde(default)]
    credentials_path: Option<String>,
    /// Optional auth token string. Carrying a `${cred://…}` token
    /// here is the most common per-caller path — the issuer plugin
    /// returns a JWT or static token that the plugin attaches via
    /// NATS auth callback at connect time.
    #[serde(default)]
    auth_token: Option<String>,
    subject: String,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    #[serde(default = "default_max_response_bytes")]
    max_response_bytes: usize,
}

/// Default per-call timeout. Matches the gateway binding default
/// (`default_binding_timeout_ms`) 1:1, so a binding that omits
/// `timeout_ms` resolves to the identical value the gateway materialized
/// before the plugin owned the default.
fn default_timeout_ms() -> u64 {
    2_000
}
/// Default response cap, matching the gateway's
/// `default_nats_max_response_bytes` (64 KiB) 1:1.
fn default_max_response_bytes() -> usize {
    65_536
}

/// Per-profile runtime state. Cloned on every execute_inner so the
/// in-flight call can safely outlive a hot-reload that replaces
/// `profiles[backend_name]`. The dynamic-cred fields (Arc-backed
/// registry, subscription guard, sweeper guard) are cheap to clone.
#[derive(Clone)]
struct NatsProfileRuntime {
    subject: String,
    timeout: Duration,
    max_response_bytes: usize,
    /// Snapshot of the operator's spec — kept on the runtime so the
    /// per-call resolver can re-walk the URL / credentials_path /
    /// auth_token values for `${cred://…}` token substitution.
    cfg: Arc<NatsBackendSpec>,
    /// True when the spec's URL / credentials_path / auth_token
    /// carry at least one `${cred://…}` token. False profiles
    /// short-circuit per-call resolution entirely (the static
    /// `client` field below is the only one ever used) and the
    /// registry never grows.
    has_cred_refs: bool,
    /// Static-cred client. Either the constructor-provided shared
    /// client or, when the spec carries its own URL with no
    /// `${cred://…}` token, a per-profile client built at register
    /// time. Used when `has_cred_refs == false`.
    static_client: Arc<async_nats::Client>,
    /// Backend host capability — only the dynamic-cred path uses
    /// it (for `resolve_credentials`). Static-cred profiles never
    /// dereference this field.
    host: Arc<dyn mcpg_plugin_protocol::BackendHost>,
    /// Per-credential client cache. Always present so the dynamic
    /// path is uniformly available; static profiles never grow it.
    client_registry: Arc<client_registry::ClientRegistry>,
    /// Revocation subscription guard. Held for the lifetime of the
    /// profile so the subscription is dropped on profile teardown.
    _revocation_sub: Arc<mcpg_plugin_protocol::CredentialRevocationSubscription>,
    /// Secret-rotation subscription guard. Drop = unsubscribe.
    _rotation_sub: Arc<mcpg_plugin_protocol::SecretRotationSubscription>,
    /// Idle-pool sweeper guard. Last reference dropped triggers
    /// task cancel.
    _idle_sweeper: Arc<IdleSweeper>,
}

/// `BackendPlugin` implementation for `kind: "nats"`.
pub struct NatsBackendPlugin {
    manifest: PluginManifest,
    /// Lazily-established shared client. `new()` (static / test path)
    /// seeds it eagerly with the gateway-built client; `from_config_json`
    /// (cdylib path) leaves it `None` and the client is connected on
    /// first `register_profile`/`execute` from `conn_url`/`conn_creds`
    /// — the cdylib factory must be infallible + sync, so the async
    /// `connect` is deferred.
    shared_client: Arc<tokio::sync::Mutex<Option<Arc<async_nats::Client>>>>,
    /// Connection params for the lazy cdylib path (`None` on the eager
    /// constructor path, which already holds a live client).
    conn_url: Option<String>,
    conn_creds: Option<String>,
    profiles: RwLock<std::collections::BTreeMap<String, NatsProfileRuntime>>,
}

impl NatsBackendPlugin {
    /// Build a new plugin instance sharing the given (eagerly-connected)
    /// NATS client. Used by tests; the cdylib path uses
    /// [`from_config_json`](Self::from_config_json) instead.
    pub fn new(client: Arc<async_nats::Client>) -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.nats",
                name: "NATS Binding",
                class: Backend,
            },
            shared_client: Arc::new(tokio::sync::Mutex::new(Some(client))),
            conn_url: None,
            conn_creds: None,
            profiles: RwLock::new(std::collections::BTreeMap::new()),
        }
    }

    /// Infallible cdylib factory: store connection params + defer the
    /// async `connect` to first use. Bad/missing config yields an
    /// instance whose first client build returns a clear transport
    /// error rather than failing the plugin load.
    pub fn from_config_json(config_json: &str) -> Self {
        // Fail CLOSED: a present-but-malformed `config:` block refuses the
        // plugin (panic → null handle) rather than silently degrading to
        // defaults. An empty/absent block still yields `Default`.
        let cfg: NatsPluginConfig =
            mcpg_plugin_sdk::fail_closed_config!(config_json, NatsPluginConfig);
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.nats",
                name: "NATS Binding",
                class: Backend,
            },
            shared_client: Arc::new(tokio::sync::Mutex::new(None)),
            conn_url: (!cfg.url.is_empty()).then_some(cfg.url),
            conn_creds: cfg.credentials_path,
            profiles: RwLock::new(std::collections::BTreeMap::new()),
        }
    }

    /// Get the shared client, connecting + caching it on first call
    /// (lazy cdylib path). Returns a transport error if no URL was
    /// configured or the connection fails.
    async fn shared_client(&self) -> Result<Arc<async_nats::Client>, BackendError> {
        {
            let guard = self.shared_client.lock().await;
            if let Some(c) = guard.as_ref() {
                return Ok(Arc::clone(c));
            }
        }
        let url = self
            .conn_url
            .as_deref()
            .ok_or_else(|| BackendError::Transport {
                message: "NATS plugin has no `url` configured; set it on the NATS binding \
                      (the gateway injects it into the plugin config)"
                    .into(),
            })?;
        let client = connect(url, self.conn_creds.as_deref())
            .await
            .map_err(|e| BackendError::Transport {
                message: format!("connecting to NATS at {}: {e}", redact_url_password(url)),
            })?;
        let mut guard = self.shared_client.lock().await;
        // Double-check: another caller may have connected while we awaited.
        if let Some(c) = guard.as_ref() {
            return Ok(Arc::clone(c));
        }
        *guard = Some(Arc::clone(&client));
        Ok(client)
    }
}

impl std::fmt::Debug for NatsBackendPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NatsBackendPlugin")
            .field("id", &self.manifest.id)
            .finish()
    }
}

#[async_trait]
impl BackendPlugin for NatsBackendPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        "nats"
    }

    async fn register_profile(
        &self,
        backend_name: &str,
        spec: &serde_json::Value,
        host: std::sync::Arc<dyn mcpg_plugin_protocol::BackendHost>,
    ) -> Result<(), BackendError> {
        let parsed: NatsBackendSpec =
            serde_json::from_value(spec.clone()).map_err(|e| BackendError::InvalidSpec {
                message: format!("NATS binding spec: {e}"),
            })?;

        if parsed.subject.trim().is_empty() {
            return Err(BackendError::InvalidSpec {
                message: "subject must not be empty".into(),
            });
        }
        if parsed.subject.contains(' ') {
            return Err(BackendError::InvalidSpec {
                message: "subject must not contain spaces".into(),
            });
        }
        if parsed.timeout_ms == 0 {
            return Err(BackendError::InvalidSpec {
                message: "timeout_ms must be greater than 0".into(),
            });
        }
        if parsed.max_response_bytes == 0 {
            return Err(BackendError::InvalidSpec {
                message: "max_response_bytes must be greater than 0".into(),
            });
        }

        // `subject` is a transport-only routing fact: the plugin treats it
        // as a plaintext NATS subject, never as a credential carrier (it is
        // never offered to `host.resolve_credentials` — see
        // `resolve_client_for_call`). A `cred://` ref there is an operator
        // mistake that would publish a resolved secret onto the wire as the
        // subject name. The gateway also enforces this generically via the
        // manifest `transport_only_fields` declaration (`/subject`); this is
        // the owning plugin's matching reject. The credential-bearing fields
        // (`url` / `credentials_path` / `auth_token`) are deliberately NOT
        // rejected here — they accept `${cred://issuer/target}` tokens for
        // the per-caller credential path.
        if parsed.subject.contains("cred://") {
            return Err(BackendError::InvalidSpec {
                message: "subject must not contain a cred:// reference".into(),
            });
        }

        let has_cred_refs = spec_has_cred_refs(&parsed);

        // Build the static client for this profile. Operators with
        // no `${cred://…}` token get the constructor's shared client
        // (today's behaviour). Operators with a per-binding URL
        // override get a freshly built client at register time. The
        // dynamic-cred path never uses this — it goes through
        // client_registry instead.
        let static_client: Arc<async_nats::Client> = if !has_cred_refs && parsed.url.is_some() {
            let url = parsed.url.as_deref().unwrap_or("");
            connect(url, parsed.credentials_path.as_deref())
                .await
                .map_err(|e| BackendError::Transport {
                    message: format!("connecting to NATS at {}: {e}", redact_url_password(url)),
                })?
        } else {
            self.shared_client().await?
        };

        // Capture the runtime this `register_profile` runs on so the
        // revocation/rotation callbacks — which fire LATER, off-runtime
        // when invoked across the cdylib FFI seam — spawn their eviction
        // tasks onto a known executor (gateway runtime on the static
        // path; the plugin's private bridge runtime on the cdylib path).
        let spawn_handle = tokio::runtime::Handle::current();

        let client_registry = Arc::new(client_registry::ClientRegistry::new(
            client_registry::ClientRegistryConfig::default(),
        ));

        // Subscribe to credential revocation events. The closure
        // routes (plugin_id, target) invalidations to the
        // registry's evict_for; the guard is held in the profile
        // so unsubscription happens at profile teardown.
        let registry_for_cb = Arc::clone(&client_registry);
        let revocation_spawn = spawn_handle.clone();
        let revocation_sub =
            host.subscribe_credential_revoked(Arc::new(move |plugin_id: &str, target: &str| {
                let registry = Arc::clone(&registry_for_cb);
                let plugin_id = plugin_id.to_owned();
                let target = target.to_owned();
                revocation_spawn.spawn(async move {
                    let evicted = registry.evict_for(&plugin_id, &target).await;
                    if evicted > 0 {
                        tracing::info!(
                            target: "mcpg::nats::client_registry",
                            plugin_id = %plugin_id,
                            target = %target,
                            evicted = evicted,
                            "evicted NATS clients on credential revocation"
                        );
                    }
                });
            }));

        // Secret rotation. Same shape as the HTTP/SQL subscribers —
        // read the gateway-injected URI hint, scope the eviction to
        // those URIs.
        let rotation_secret_refs: Vec<String> = spec
            .get("__mcpg_secret_refs")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let registry_for_rotation = Arc::clone(&client_registry);
        let secret_refs_for_cb: Arc<Vec<String>> = Arc::new(rotation_secret_refs);
        let rotation_spawn = spawn_handle.clone();
        let rotation_sub =
            host.subscribe_secret_rotation(Arc::new(move |secret_ref: &str, version: u64| {
                if !secret_refs_for_cb.iter().any(|r| r == secret_ref) {
                    return;
                }
                let registry = Arc::clone(&registry_for_rotation);
                let secret_ref = secret_ref.to_owned();
                rotation_spawn.spawn(async move {
                    let evicted = registry.evict_for_secret(&secret_ref).await;
                    if evicted > 0 {
                        tracing::info!(
                            target: "mcpg::nats::client_registry",
                            secret_ref = %secret_ref,
                            version = version,
                            evicted = evicted,
                            "evicted NATS clients on secret rotation"
                        );
                    }
                });
            }));

        let idle_sweeper = spawn_idle_sweeper(
            backend_name.to_owned(),
            Arc::clone(&client_registry),
            Duration::from_secs(60),
        );

        debug!(
            backend = %backend_name,
            subject = %parsed.subject,
            timeout_ms = parsed.timeout_ms,
            has_cred_refs = has_cred_refs,
            "registered NATS binding profile"
        );

        let runtime = NatsProfileRuntime {
            subject: parsed.subject.clone(),
            timeout: Duration::from_millis(parsed.timeout_ms),
            max_response_bytes: parsed.max_response_bytes,
            cfg: Arc::new(parsed),
            has_cred_refs,
            static_client,
            host,
            client_registry,
            _revocation_sub: Arc::new(revocation_sub),
            _rotation_sub: Arc::new(rotation_sub),
            _idle_sweeper: idle_sweeper,
        };
        self.profiles
            .write()
            .await
            .insert(backend_name.to_owned(), runtime);
        Ok(())
    }

    async fn execute(
        &self,
        backend_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        // Wrap full NATS request/reply in a plugin-scoped span.
        // Subject is recorded so traces attribute to the topic
        // and to `dev.mcpg.backend.nats`.
        let span = info_span!(
            "nats_binding_execute",
            plugin_id = "dev.mcpg.backend.nats",
            backend = %backend_name,
        );
        let started = std::time::Instant::now();
        let result = self
            .execute_inner(backend_name, request)
            .instrument(span)
            .await;
        let elapsed = started.elapsed();

        let (outcome, error_kind) = match &result {
            Ok(_) => ("ok", "none"),
            Err(BackendError::Timeout { .. }) => ("error", "timeout"),
            Err(BackendError::Transport { .. }) => ("error", "transport"),
            Err(BackendError::ProfileNotFound { .. }) => ("error", "profile_not_found"),
            Err(BackendError::InvalidSpec { .. }) => ("error", "invalid_spec"),
        };
        metrics::counter!(
            "mcpg_nats_binding_calls_total",
            "backend" => backend_name.to_owned(),
            "outcome" => outcome,
            "error_kind" => error_kind,
        )
        .increment(1);
        metrics::histogram!(
            "mcpg_nats_binding_call_ms",
            "backend" => backend_name.to_owned(),
            "outcome" => outcome,
        )
        .record(elapsed.as_millis() as f64);

        match &result {
            Ok(_) => debug!(
                backend = %backend_name,
                elapsed_ms = %elapsed.as_millis(),
                "NATS binding call succeeded"
            ),
            Err(e) => warn!(
                backend = %backend_name,
                error = %e,
                "NATS binding call failed"
            ),
        }

        result
    }
}

impl NatsBackendPlugin {
    async fn execute_inner(
        &self,
        backend_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        let profile = {
            let guard = self.profiles.read().await;
            guard
                .get(backend_name)
                .cloned()
                .ok_or_else(|| BackendError::ProfileNotFound {
                    backend_name: backend_name.to_owned(),
                })?
        };

        // defence-in-depth — reject wildcards in the subject. Current
        // subjects come from static config, but this guards against a
        // future CEL-interpolated subject containing a wildcard.
        if profile.subject.contains('*') || profile.subject.contains('>') {
            return Err(BackendError::InvalidSpec {
                message: format!(
                    "NATS subject '{}' for binding '{}' contains wildcard characters",
                    profile.subject, backend_name,
                ),
            });
        }

        // Per-cred client resolution. Static profiles
        // short-circuit to the constructor-provided shared client;
        // dynamic-cred profiles resolve their `${cred://…}` tokens
        // through the host and look up / build a client from the
        // registry keyed on the resolved-credential digest.
        let client: Arc<async_nats::Client> = if profile.has_cred_refs {
            resolve_client_for_call(&profile, &request, backend_name).await?
        } else {
            Arc::clone(&profile.static_client)
        };

        let payload = bytes::Bytes::from(request.payload);

        let mut headers = async_nats::HeaderMap::new();
        for (name, value) in &request.headers {
            headers.insert(name.as_str(), value.as_str());
        }
        // Propagate the gateway-supplied idempotency hint as
        // application headers. Lowercase (`idempotency-key`,
        // `idempotency-scope-hash`) per the common NATS / Kafka
        // ecosystem convention; NATS headers are case-sensitive, so
        // the casing matters and must match what consumer-side dedupe
        // code is going to look for.
        //
        // Note we do NOT set `Nats-Msg-Id` automatically — that's
        // a JetStream-specific header for broker-level dedup
        // (stream-config opt-in on the JetStream side). Operators
        // wanting JetStream broker dedup configure the stream's
        // `discard_new_per_subject` / dedup window; a per-binding
        // `nats_jetstream_msg_id: true` switch is a possible future
        // follow-up. See the design doc §3 for the distinction.
        if let Some(hint) = request.idempotency.as_ref() {
            headers.insert("idempotency-key", hint.key.as_str());
            headers.insert("idempotency-scope-hash", hint.scope_hash.as_str());
        }
        let has_headers = !request.headers.is_empty() || request.idempotency.is_some();

        let reply = if has_headers {
            tokio::time::timeout(
                profile.timeout,
                client.request_with_headers(profile.subject.clone(), headers, payload),
            )
            .await
        } else {
            tokio::time::timeout(
                profile.timeout,
                client.request(profile.subject.clone(), payload),
            )
            .await
        };

        match reply {
            Ok(Ok(message)) => {
                let response_bytes = message.payload.len();
                let (payload, truncated) = if response_bytes > profile.max_response_bytes {
                    warn!(
                        subject = %profile.subject,
                        backend = %backend_name,
                        response_bytes,
                        max_bytes = profile.max_response_bytes,
                        "NATS response exceeded max_response_bytes — truncating"
                    );
                    (
                        message.payload.slice(..profile.max_response_bytes).to_vec(),
                        true,
                    )
                } else {
                    (message.payload.to_vec(), false)
                };
                Ok(BackendResponse { payload, truncated })
            }
            Ok(Err(e)) => Err(BackendError::Transport {
                message: format!("NATS request to '{}' failed: {e}", profile.subject),
            }),
            Err(_) => Err(BackendError::Timeout {
                timeout_ms: profile.timeout.as_millis() as u64,
            }),
        }
    }
}

/// True when the spec's URL / credentials_path / auth_token carry at
/// least one `${cred://issuer/target}` token. A BARE `cred://…` (not
/// wrapped in `${}`) is NOT a credential reference — it travels to
/// NATS verbatim and does not flip on the per-credential path.
fn spec_has_cred_refs(spec: &NatsBackendSpec) -> bool {
    let has_token = |s: &Option<String>| s.as_deref().is_some_and(|v| !cred_tokens(v).is_empty());
    has_token(&spec.url) || has_token(&spec.credentials_path) || has_token(&spec.auth_token)
}

/// Per-call client resolution. Collects the `${cred://…}` tokens the
/// operator baked into the URL / credentials_path / auth_token, asks
/// the host to resolve those token URIs per caller identity, then
/// substitutes each token back into the config strings and looks up /
/// builds a client from the registry keyed on a BLAKE3 digest of the
/// resolved bundle.
async fn resolve_client_for_call(
    profile: &NatsProfileRuntime,
    request: &BackendRequest,
    backend_name: &str,
) -> Result<Arc<async_nats::Client>, BackendError> {
    let cfg = &profile.cfg;
    // Standardized credential grammar: only `${cred://issuer/target}`
    // tokens in the operator config resolve. A BARE `cred://…` is left
    // verbatim — never offered to the host. `cred_tokens` extracts the
    // inner `cred://…` URI from every `${cred://…}` token (and ignores
    // bare cred://), so the snapshot is config-origin BY CONSTRUCTION.
    //
    // SECURITY (F1 — credential-snapshot provenance): the snapshot handed
    // to `host.resolve_credentials` MUST contain only OPERATOR-CONFIG-ORIGIN
    // values. The host substitutes ANY `cred://` it finds, per caller
    // identity, with no config whitelist — so a request-arg-derived value
    // smuggled in here would let a malicious caller exfiltrate a configured
    // credential (for a static issuer, the secret itself). We collect tokens
    // ONLY from the operator's `url` / `credentials_path` / `auth_token`
    // literals (parsed once at `register_profile`, never re-templated against
    // request args), and insert ONLY those token URIs into the snapshot. The
    // request's tool-arguments body + headers travel separately in
    // `execute_inner` and never enter this snapshot. See the standardized
    // grammar in net-core
    // (`libs/plugins/backend/net-core/src/runtime.rs::resolve_client`) and the
    // regression `tests/cred_snapshot_provenance.rs`.
    let mut cred_uris: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for value in [
        cfg.url.as_deref(),
        cfg.credentials_path.as_deref(),
        cfg.auth_token.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        for uri in cred_tokens(value) {
            cred_uris.insert(uri);
        }
    }

    // Resolve those token URIs through the host, per caller identity, in
    // one call → `uri → resolved value`. The snapshot is keyed by the
    // bare inner URI so the host's "substitute every cred://" contract
    // resolves exactly the tokens the operator wrote — nothing else.
    let cred_map: std::collections::HashMap<String, String> = if cred_uris.is_empty() {
        std::collections::HashMap::new()
    } else {
        let mut snapshot = serde_json::Map::new();
        for uri in &cred_uris {
            snapshot.insert(uri.clone(), serde_json::Value::String(uri.clone()));
        }
        let mut snapshot = serde_json::Value::Object(snapshot);

        let mut host_ctx = mcpg_plugin_protocol::BackendInvocationContext::root(
            request.request_id.clone(),
            request.session_id.clone(),
            backend_name.to_owned(),
        );
        host_ctx.identity = request.identity.clone();
        profile
            .host
            .resolve_credentials(&host_ctx, &mut snapshot)
            .await
            .map_err(|e| match e {
                mcpg_plugin_protocol::BackendHostError::Backend { cause, .. } => cause,
                other => BackendError::Transport {
                    message: format!("credential resolution: {other}"),
                },
            })?;

        snapshot
            .as_object()
            .ok_or_else(|| BackendError::Transport {
                message: "credential resolver mutated snapshot to non-object".into(),
            })?
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
            .collect()
    };

    // Substitute each `${cred://…}` token back into the config strings
    // from the resolved map. Tokens absent from the map (i.e. the host
    // declined them) and bare `cred://…` are left verbatim.
    let resolved_url = cfg
        .url
        .as_deref()
        .map(|u| substitute_cred_tokens(u, &cred_map));
    let resolved_creds_path = cfg
        .credentials_path
        .as_deref()
        .map(|p| substitute_cred_tokens(p, &cred_map));
    let resolved_auth_token = cfg
        .auth_token
        .as_deref()
        .map(|t| substitute_cred_tokens(t, &cred_map));

    // The connect URL: prefer the resolved per-binding URL; fall
    // back to the constructor-provided shared client URL — but we
    // can't read that back from `async_nats::Client`. So when the
    // spec carries no URL field, the dynamic path is unsupported.
    // (`spec_has_cred_refs` already guarded against this case for
    // url alone, but credentials_path / auth_token may have triggered
    // the path with no URL field at all.)
    let connect_url = resolved_url
        .clone()
        .ok_or_else(|| BackendError::InvalidSpec {
            message:
                "NATS binding with a ${cred://…} token in credentials_path or auth_token also \
                  requires a `url` field on the spec — the per-credential path needs an explicit \
                  connect URL"
                    .into(),
        })?;

    // Build the digest pairs from the resolved bundle. URL is
    // always included; credentials_path + auth_token join in when
    // present.
    let mut digest_pairs: Vec<(String, String)> = Vec::with_capacity(3);
    digest_pairs.push(("url".into(), connect_url.clone()));
    if let Some(p) = resolved_creds_path.as_deref() {
        digest_pairs.push(("credentials_path".into(), p.to_owned()));
    }
    if let Some(t) = resolved_auth_token.as_deref() {
        digest_pairs.push(("auth_token".into(), t.to_owned()));
    }
    let digest: CredDigest = digest_credential_bundle(&digest_pairs);

    // Cred-keys are the (plugin_id, target) pairs from the pre-
    // resolution config tokens — used to route revocation events to
    // the right registry entry. Derived from the same `${cred://…}`
    // tokens that drove resolution (`cred_uris`), so a bare `cred://…`
    // never registers a revocation key (it was never resolved).
    let mut cred_keys: Vec<(String, String)> = cred_uris
        .iter()
        .filter_map(|uri| CredRef::parse(uri).map(|r| (r.plugin_id, r.target)))
        .collect();
    cred_keys.sort();
    cred_keys.dedup();

    let creds_path_for_build = resolved_creds_path.clone();
    let auth_token_for_build = resolved_auth_token.clone();
    let url_for_build = connect_url.clone();
    profile
        .client_registry
        .get_or_build(digest, cred_keys, || async move {
            let client = build_nats_client(
                &url_for_build,
                creds_path_for_build.as_deref(),
                auth_token_for_build.as_deref(),
            )
            .await?;
            Ok(client)
        })
        .await
        .map_err(|e| BackendError::Transport {
            message: format!("building per-credential NATS client: {e}"),
        })
}

/// Connect with optional credentials_path and/or auth_token. When
/// auth_token is set, attaches a NATS auth callback that returns the
/// token verbatim — async-nats invokes it on every reconnect.
async fn build_nats_client(
    url: &str,
    credentials_path: Option<&str>,
    auth_token: Option<&str>,
) -> Result<Arc<async_nats::Client>> {
    let mut options = if let Some(creds) = credentials_path {
        async_nats::ConnectOptions::with_credentials_file(PathBuf::from(creds))
            .await
            .with_context(|| format!("loading NATS credentials from {creds}"))?
    } else {
        async_nats::ConnectOptions::new()
    };
    if let Some(token) = auth_token {
        options = options.token(token.to_owned());
    }
    let client = options
        .connect(url)
        .await
        .with_context(|| format!("connecting to NATS at {}", redact_url_password(url)))?;
    Ok(Arc::new(client))
}

// ---------------------------------------------------------------------------
// Watch-strategy plugin — NATS topic subscription
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct NatsWatchSpec {
    subject: String,
}

/// `WatchStrategyPlugin` implementation for `kind: "nats_topic"`.
pub struct NatsWatchPlugin {
    manifest: PluginManifest,
    /// Lazily-established client (see [`NatsBackendPlugin`] for the
    /// eager-vs-lazy rationale). Built on first `watch()`.
    client: Arc<tokio::sync::Mutex<Option<Arc<async_nats::Client>>>>,
    conn_url: Option<String>,
    conn_creds: Option<String>,
}

impl NatsWatchPlugin {
    /// Build a watch plugin sharing the given (eagerly-connected) NATS
    /// client. Used by tests; the cdylib path uses
    /// [`from_config_json`](Self::from_config_json).
    pub fn new(client: Arc<async_nats::Client>) -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.watch.nats_topic",
                name: "NATS Topic Watch",
                class: WatchStrategy,
            },
            client: Arc::new(tokio::sync::Mutex::new(Some(client))),
            conn_url: None,
            conn_creds: None,
        }
    }

    /// Infallible cdylib factory: defer the async `connect` to first
    /// `watch()`.
    pub fn from_config_json(config_json: &str) -> Self {
        // Fail CLOSED: a present-but-malformed `config:` block refuses the
        // plugin rather than silently degrading to defaults. An
        // empty/absent block still yields `Default`.
        let cfg: NatsPluginConfig =
            mcpg_plugin_sdk::fail_closed_config!(config_json, NatsPluginConfig);
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.watch.nats_topic",
                name: "NATS Topic Watch",
                class: WatchStrategy,
            },
            client: Arc::new(tokio::sync::Mutex::new(None)),
            conn_url: (!cfg.url.is_empty()).then_some(cfg.url),
            conn_creds: cfg.credentials_path,
        }
    }

    /// Get the client, connecting + caching on first call.
    async fn client(&self) -> Result<Arc<async_nats::Client>, WatchError> {
        {
            let guard = self.client.lock().await;
            if let Some(c) = guard.as_ref() {
                return Ok(Arc::clone(c));
            }
        }
        let url = self
            .conn_url
            .as_deref()
            .ok_or_else(|| WatchError::Subscribe {
                message: "NATS watch plugin has no `url` configured; set it on the NATS binding"
                    .into(),
            })?;
        let client = connect(url, self.conn_creds.as_deref())
            .await
            .map_err(|e| WatchError::Subscribe {
                message: format!("connecting to NATS at {}: {e}", redact_url_password(url)),
            })?;
        let mut guard = self.client.lock().await;
        if let Some(c) = guard.as_ref() {
            return Ok(Arc::clone(c));
        }
        *guard = Some(Arc::clone(&client));
        Ok(client)
    }
}

impl std::fmt::Debug for NatsWatchPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NatsWatchPlugin")
            .field("id", &self.manifest.id)
            .finish()
    }
}

struct NatsWatchHandle {
    cancel: CancellationToken,
}

#[async_trait]
impl WatchHandle for NatsWatchHandle {
    async fn cancel(&self) {
        self.cancel.cancel();
    }
}

#[async_trait]
impl WatchStrategyPlugin for NatsWatchPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        "nats_topic"
    }

    async fn watch(
        &self,
        resource_uri: &str,
        spec: &serde_json::Value,
        sink: Arc<dyn WatchEventSink>,
    ) -> Result<Box<dyn WatchHandle>, WatchError> {
        // Wrap subscribe in a plugin-scoped span so the initial
        // subscribe trace + the long-lived event-loop span attribute
        // back to dev.mcpg.watch.nats_topic.
        let span = info_span!(
            "nats_watch_subscribe",
            plugin_id = "dev.mcpg.watch.nats_topic",
            resource_uri = %resource_uri,
        );
        async {
            let parsed: NatsWatchSpec =
                serde_json::from_value(spec.clone()).map_err(|e| WatchError::InvalidSpec {
                    message: format!("NATS watch spec: {e}"),
                })?;

            if parsed.subject.trim().is_empty() {
                return Err(WatchError::InvalidSpec {
                    message: "subject must not be empty".into(),
                });
            }

            let started = std::time::Instant::now();
            let client = self.client().await?;
            let mut subscription = client
                .subscribe(parsed.subject.clone())
                .await
                .map_err(|e| {
                    metrics::counter!(
                        "mcpg_nats_watch_subscribes_total",
                        "outcome" => "error",
                    )
                    .increment(1);
                    WatchError::Subscribe {
                        message: format!(
                            "failed to subscribe to NATS subject '{}': {e}",
                            parsed.subject
                        ),
                    }
                })?;

            metrics::counter!(
                "mcpg_nats_watch_subscribes_total",
                "outcome" => "ok",
            )
            .increment(1);
            metrics::histogram!("mcpg_nats_watch_subscribe_ms")
                .record(started.elapsed().as_millis() as f64);

            info!(
                uri = %resource_uri,
                subject = %parsed.subject,
                "NATS watch: subscribed"
            );

            let cancel = CancellationToken::new();
            let cancel_child = cancel.clone();
            let uri_owned = resource_uri.to_owned();
            let subject_owned = parsed.subject;

            // Long-lived watch loop — own its own span so events
            // emitted from the loop attribute back to the watch
            // plugin id.
            let loop_span = info_span!(
                "nats_watch_loop",
                plugin_id = "dev.mcpg.watch.nats_topic",
                uri = %uri_owned,
            );
            tokio::spawn(
                async move {
                    loop {
                        tokio::select! {
                            _ = cancel_child.cancelled() => {
                                debug!(uri = %uri_owned, "NATS watch: cancelled");
                                if let Err(e) = subscription.unsubscribe().await {
                                    debug!(error = %e, "NATS watch: unsubscribe error");
                                }
                                return;
                            }
                            msg = subscription.next() => {
                                match msg {
                                    Some(_nats_msg) => {
                                        metrics::counter!(
                                            "mcpg_nats_watch_events_total",
                                        )
                                        .increment(1);
                                        sink.emit(WatchEvent::default()).await;
                                    }
                                    None => {
                                        // async-nats auto-reconnects the
                                        // underlying connection, so a `None`
                                        // here means the subscription stream
                                        // itself ended (client closed/drained)
                                        // and won't resume — terminate the
                                        // loop rather than spin on a dead
                                        // stream. The host re-establishes the
                                        // watch on the next resolve cycle.
                                        warn!(
                                            uri = %uri_owned,
                                            subject = %subject_owned,
                                            "NATS watch: subscription closed"
                                        );
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
                .instrument(loop_span),
            );

            Ok(Box::new(NatsWatchHandle { cancel }) as Box<dyn WatchHandle>)
        }
        .instrument(span)
        .await
    }
}

// ---------------------------------------------------------------------------
// cdylib sync bridge — adapts the async `BackendPlugin` /
// `WatchStrategyPlugin` impls onto the sync FFI traits the cdylib vtable
// expects. Each wrapper owns a private multi-thread runtime and
// `block_on`s the async logic; the backend wrapper derives an
// `Arc<dyn BackendHost>` from the make-time `HostHandle` (via
// `HostHandleBackendHost`) for credential resolution + revocation /
// rotation subscriptions through the v31 host-FFI slots. Mirrors the
// kafka pilot (libs/plugins/backend/kafka).
// ---------------------------------------------------------------------------

fn build_bridge_runtime(thread_name: &str) -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name(thread_name.to_owned())
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("nats cdylib: tokio runtime init failed: {e}"))
}

/// `SyncBackendPlugin` bridge over [`NatsBackendPlugin`].
pub struct NatsBackendCdylib {
    inner: NatsBackendPlugin,
    host: Arc<dyn mcpg_plugin_protocol::BackendHost>,
    rt: tokio::runtime::Runtime,
}

impl NatsBackendCdylib {
    pub fn from_host_config(config_json: &str, host: HostHandle) -> Self {
        Self {
            inner: NatsBackendPlugin::from_config_json(config_json),
            host: Arc::new(HostHandleBackendHost::new(host)),
            rt: build_bridge_runtime("mcpg-backend-nats"),
        }
    }
}

impl SyncBackendPlugin for NatsBackendCdylib {
    fn manifest(&self) -> &PluginManifest {
        BackendPlugin::manifest(&self.inner)
    }
    fn kind(&self) -> &str {
        BackendPlugin::kind(&self.inner)
    }
    fn register_profile(
        &self,
        profile_name: &str,
        spec: &serde_json::Value,
    ) -> Result<(), BackendError> {
        self.rt.block_on(BackendPlugin::register_profile(
            &self.inner,
            profile_name,
            spec,
            Arc::clone(&self.host),
        ))
    }
    fn execute(
        &self,
        profile_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        self.rt
            .block_on(BackendPlugin::execute(&self.inner, profile_name, request))
    }
}

/// Async `WatchEventSink` forwarding each event to the cdylib FFI
/// push-callback (serialized `WatchEvent` JSON).
struct ClosureWatchSink {
    emit: Box<dyn Fn(&str) + Send + Sync + 'static>,
}

#[async_trait]
impl WatchEventSink for ClosureWatchSink {
    async fn emit(&self, event: WatchEvent) {
        match serde_json::to_string(&event) {
            Ok(json) => (self.emit)(&json),
            Err(e) => warn!(error = %e, "nats watch: failed to serialize WatchEvent; dropping"),
        }
    }
}

/// Cancel state boxed behind the opaque [`WatchHandleBox`] pointer.
struct WatchCancelState {
    handle: Box<dyn WatchHandle>,
    rt: tokio::runtime::Handle,
}

/// `SyncWatchStrategyPlugin` bridge over [`NatsWatchPlugin`].
pub struct NatsWatchCdylib {
    inner: NatsWatchPlugin,
    rt: tokio::runtime::Runtime,
}

impl NatsWatchCdylib {
    pub fn from_host_config(config_json: &str, _host: HostHandle) -> Self {
        Self {
            inner: NatsWatchPlugin::from_config_json(config_json),
            rt: build_bridge_runtime("mcpg-watch-nats"),
        }
    }
}

impl SyncWatchStrategyPlugin for NatsWatchCdylib {
    fn manifest(&self) -> &PluginManifest {
        WatchStrategyPlugin::manifest(&self.inner)
    }
    fn kind(&self) -> &str {
        WatchStrategyPlugin::kind(&self.inner)
    }
    fn watch(
        &self,
        resource_uri: &str,
        spec: &serde_json::Value,
        emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    ) -> Result<WatchHandleBox, WatchError> {
        let sink = Arc::new(ClosureWatchSink { emit: emit_event });
        let handle = self.rt.block_on(WatchStrategyPlugin::watch(
            &self.inner,
            resource_uri,
            spec,
            sink,
        ))?;
        let state = Box::new(WatchCancelState {
            handle,
            rt: self.rt.handle().clone(),
        });
        Ok(WatchHandleBox(Box::into_raw(state) as *mut ()))
    }
    fn cancel(&self, watch_handle: WatchHandleBox) {
        if watch_handle.0.is_null() {
            return;
        }
        // SAFETY: pointer produced by `Box::into_raw` in `watch`, round-
        // tripped by the host exactly once.
        let state = unsafe { Box::from_raw(watch_handle.0 as *mut WatchCancelState) };
        state.rt.block_on(state.handle.cancel());
    }
}

// cdylib export — both entities under `dev.mcpg.backend.nats`; the watch
// entity (id `dev.mcpg.watch.nats_topic`) is distinguished by
// `inner_name: "watch"` and self-describes via its `manifest()` slot.
mcpg_plugin_sdk::declare_plugin! {
    plugin_id: "dev.mcpg.backend.nats",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: BINDING_DESCRIPTOR_YAML,
    capabilities: &[::mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    // Residual per-kind facts the gateway reads back by kind. NATS is a
    // request/reply messaging transport, not a probe-able HTTP/TCP
    // endpoint — health is tracked separately, so the active probe is
    // Skip (the default). It is pipeline-capable (a `kind: nats` pipeline
    // step). label defaults to the kind ("nats"), no dynamic tool list.
    // `subject` is the one transport-only routing fact — the gateway's
    // generic spec-walk asserts no `cred://` lands there; `url` /
    // `credentials_path` / `auth_token` are intentionally absent (they
    // legitimately carry per-caller `${cred://…}` tokens).
    //
    // The connection-vs-per-binding SPLIT lives entirely in this plugin:
    // CONNECTION fields (`url`, `credentials_path`) arrive via the
    // `plugins[].config` block the host passes to the cdylib factory
    // (`from_config_json` → `conn_url`/`conn_creds`, the lazy shared
    // client); PER-BINDING fields (`subject`, `timeout_ms`,
    // `max_response_bytes`, plus the optional per-caller cred overrides)
    // arrive in the `register_profile` spec. The gateway used to encode
    // this split by injecting the first binding's connection fields into
    // the plugin entry config and stripping them from the per-binding
    // spec; under the generic model the same data flows through the same
    // two seams, but the plugin — not the gateway — owns it.
    backend_profile: ::mcpg_plugin_protocol::manifest::BackendProfile {
        pipeline_capable: true,
        transport_only_fields: ::std::vec!["/subject".to_owned()],
        ..::core::default::Default::default()
    },
    entities: [
        backend as binding {
            inner_name: "",
            plugin_type: NatsBackendCdylib,
            factory: |cfg, host: ::mcpg_plugin_sdk::HostHandle|
                NatsBackendCdylib::from_host_config(cfg, host),
        },
        watch_strategy as watch {
            inner_name: "watch",
            plugin_type: NatsWatchCdylib,
            factory: |cfg, host: ::mcpg_plugin_sdk::HostHandle|
                NatsWatchCdylib::from_host_config(cfg, host),
        },
    ],
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises port allocation and server bind across the tests in this
    /// binary.
    ///
    /// `bind(:0)` reserves a port only until the listener drops, and the
    /// server binds it a moment later. Two tests racing through that window
    /// get the same port: one server binds, the other exits, and the loser
    /// then polls the port, finds the WINNER's server accepting, and connects
    /// to it — where its subject has no subscriber. The symptom is a
    /// `no responders` error nowhere near the cause, and it scales with how
    /// many tests run at once. Holding this across allocate-and-bind closes
    /// the window.
    static PORT_HANDOFF: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Helper to find a free port by binding to :0.
    fn find_free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind to :0")
            .local_addr()
            .expect("local addr")
            .port()
    }

    /// Start a NATS server on its own port, returning the child and the port.
    ///
    /// `NATS_SERVER_BIN` names the binary when the runner supplies one as a
    /// declared input, resolved against `TEST_SRCDIR` because the path is
    /// runfiles-relative and the test's working directory is not the runfiles
    /// root. Neither variable exists under `cargo test`, which falls back to a
    /// bare `nats-server` off PATH.
    /// `None` means no `nats-server` exists on this machine at all — the
    /// live-wire tests skip rather than fail, since a checkout without the
    /// server (no runfiles, nothing on PATH) cannot meaningfully run them.
    fn start_nats_server() -> Option<(std::process::Child, u16)> {
        // Poisoning only means some other test panicked; the port handoff
        // itself is still sound, so take the guard either way.
        let _guard = PORT_HANDOFF.lock().unwrap_or_else(|e| e.into_inner());
        let port = find_free_port();
        let bin = match (
            std::env::var("NATS_SERVER_BIN"),
            std::env::var("TEST_SRCDIR"),
        ) {
            (Ok(rel), Ok(root)) => format!("{root}/{rel}"),
            _ => "nats-server".to_owned(),
        };
        let mut child = match std::process::Command::new(&bin)
            .args(["-p", &port.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipped: nats-server not available as `{bin}`");
                return None;
            }
            Err(e) => panic!("failed to start nats-server: {e}"),
        };

        let addr = format!("127.0.0.1:{}", port);
        // Poll for up to 30 s (300 × 100 ms) — nats-server startup competes
        // with every other test process on a saturated CI runner, and a
        // short ceiling here is a pure flake. A plain TCP-connect check races
        // with NATS protocol initialisation: the port can be open before the
        // INFO banner is ready, which causes the first async_nats::connect()
        // call in tests to get "Connection refused". Reading one byte from the
        // stream proves the INFO handler is up and the server is truly ready.
        for _ in 0..300 {
            // Our own child exiting means it lost the port to someone else.
            // Without this the loop would happily succeed against whatever
            // server did win, and the test would fail much later with a
            // symptom that looks nothing like a port collision.
            if let Ok(Some(status)) = child.try_wait() {
                panic!("nats-server exited before accepting on port {port}: {status}");
            }
            if let Ok(mut stream) = std::net::TcpStream::connect(&addr) {
                use std::io::Read;
                let mut buf = [0u8; 1];
                if stream.read(&mut buf).is_ok() {
                    return Some((child, port));
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        // Timed out — kill the child we spawned to avoid leaking a
        // background process when the test harness panics.
        let _ = child.kill();
        let _ = child.wait();
        panic!("nats-server did not start on port {port} within 30s");
    }

    // --- Fail-closed config parsing (no NATS server needed: from_config_json
    //     only stores connection params and defers the async connect) ---

    #[test]
    fn from_config_json_empty_block_yields_defaults() {
        // Empty / unit / null blocks are an opt-out, not a typo: Default.
        for empty in ["", "{}", "   ", "null"] {
            let backend = NatsBackendPlugin::from_config_json(empty);
            assert_eq!(backend.conn_url, None, "empty config {empty:?} → no url");
            assert_eq!(
                backend.conn_creds, None,
                "empty config {empty:?} → no creds"
            );

            let watch = NatsWatchPlugin::from_config_json(empty);
            assert_eq!(
                watch.conn_url, None,
                "empty config {empty:?} → no url (watch)"
            );
            assert_eq!(
                watch.conn_creds, None,
                "empty config {empty:?} → no creds (watch)"
            );
        }
    }

    #[test]
    fn from_config_json_valid_block_parses() {
        let backend = NatsBackendPlugin::from_config_json(r#"{"url":"nats://example:4222"}"#);
        assert_eq!(backend.conn_url.as_deref(), Some("nats://example:4222"));
    }

    #[test]
    #[should_panic(expected = "failing closed")]
    fn from_config_json_malformed_fails_closed() {
        // A present-but-malformed config refuses the plugin (panic → null
        // handle) rather than silently degrading to defaults.
        let _ = NatsBackendPlugin::from_config_json("not json");
    }

    #[test]
    #[should_panic(expected = "failing closed")]
    fn watch_from_config_json_malformed_fails_closed() {
        let _ = NatsWatchPlugin::from_config_json("not json");
    }

    #[test]
    #[should_panic(expected = "failing closed")]
    fn from_config_json_unknown_key_fails_closed() {
        // `#[serde(deny_unknown_fields)]` on NatsPluginConfig turns a
        // stray / renamed / typo'd config key into a parse error, which
        // `fail_closed_config!` escalates to a panic (refuse the plugin)
        // rather than silently ignoring the bad key. `credential_path`
        // (singular) is a plausible typo of `credentials_path`.
        let _ = NatsBackendPlugin::from_config_json(
            r#"{"url":"nats://example:4222","credential_path":"/etc/creds"}"#,
        );
    }

    #[tokio::test]
    async fn binding_plugin_kind_is_nats() {
        let Some((mut server, port)) = start_nats_server() else {
            return;
        };
        let client = connect(&format!("nats://127.0.0.1:{port}"), None)
            .await
            .unwrap();
        let plugin = NatsBackendPlugin::new(client);
        assert_eq!(plugin.kind(), "nats");
        server.kill().ok();
        server.wait().ok();
    }

    #[tokio::test]
    async fn watch_plugin_kind_is_nats_topic() {
        let Some((mut server, port)) = start_nats_server() else {
            return;
        };
        let client = connect(&format!("nats://127.0.0.1:{port}"), None)
            .await
            .unwrap();
        let plugin = NatsWatchPlugin::new(client);
        assert_eq!(plugin.kind(), "nats_topic");
        server.kill().ok();
        server.wait().ok();
    }

    #[tokio::test]
    async fn register_profile_validates_spec() {
        let Some((mut server, port)) = start_nats_server() else {
            return;
        };
        let client = connect(&format!("nats://127.0.0.1:{port}"), None)
            .await
            .unwrap();
        let plugin = NatsBackendPlugin::new(client);

        let ok = plugin
            .register_profile(
                "t1",
                &serde_json::json!({
                    "subject": "mcpg.exec.request.tools.test",
                    "timeout_ms": 1000,
                    "max_response_bytes": 1024,
                }),
                mcpg_plugin_protocol::noop_backend_host(),
            )
            .await;
        assert!(ok.is_ok(), "valid spec should register: {:?}", ok);

        let empty = plugin
            .register_profile(
                "t2",
                &serde_json::json!({ "subject": "" }),
                mcpg_plugin_protocol::noop_backend_host(),
            )
            .await;
        assert!(matches!(empty, Err(BackendError::InvalidSpec { .. })));

        let spaces = plugin
            .register_profile(
                "t3",
                &serde_json::json!({ "subject": "a b" }),
                mcpg_plugin_protocol::noop_backend_host(),
            )
            .await;
        assert!(matches!(spaces, Err(BackendError::InvalidSpec { .. })));

        server.kill().ok();
        server.wait().ok();
    }

    #[tokio::test]
    async fn request_reply_round_trip() {
        let Some((mut server, port)) = start_nats_server() else {
            return;
        };
        let url = format!("nats://127.0.0.1:{port}");
        let client = connect(&url, None).await.unwrap();
        let plugin = NatsBackendPlugin::new(client);

        plugin
            .register_profile(
                "echo-tool",
                &serde_json::json!({
                    "subject": "mcpg.exec.request.tools.echo",
                    "timeout_ms": 5000,
                    "max_response_bytes": 65536,
                }),
                mcpg_plugin_protocol::noop_backend_host(),
            )
            .await
            .unwrap();

        // Worker subscribes and echoes back
        let worker = async_nats::connect(&url).await.unwrap();
        let mut sub = worker
            .subscribe("mcpg.exec.request.tools.echo")
            .await
            .unwrap();
        tokio::spawn(async move {
            if let Some(msg) = sub.next().await
                && let Some(reply) = msg.reply
            {
                worker.publish(reply, msg.payload).await.ok();
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = plugin
            .execute(
                "echo-tool",
                BackendRequest {
                    payload: b"hello".to_vec(),
                    headers: vec![],
                    request_id: "r1".into(),
                    session_id: None,
                    identity: None,
                    idempotency: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(resp.payload, b"hello");
        assert!(!resp.truncated);

        server.kill().ok();
        server.wait().ok();
    }

    #[tokio::test]
    async fn execute_without_registered_profile_errors() {
        let Some((mut server, port)) = start_nats_server() else {
            return;
        };
        let client = connect(&format!("nats://127.0.0.1:{port}"), None)
            .await
            .unwrap();
        let plugin = NatsBackendPlugin::new(client);
        let err = plugin
            .execute(
                "not-registered",
                BackendRequest {
                    payload: vec![],
                    headers: vec![],
                    request_id: "r1".into(),
                    session_id: None,
                    identity: None,
                    idempotency: None,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, BackendError::ProfileNotFound { .. }));
        server.kill().ok();
        server.wait().ok();
    }

    #[tokio::test]
    async fn request_timeout_reports_timeout_error() {
        let Some((mut server, port)) = start_nats_server() else {
            return;
        };
        let client = connect(&format!("nats://127.0.0.1:{port}"), None)
            .await
            .unwrap();
        let plugin = NatsBackendPlugin::new(client);
        plugin
            .register_profile(
                "slow",
                &serde_json::json!({
                    "subject": "mcpg.exec.request.tools.slow",
                    "timeout_ms": 100,
                    "max_response_bytes": 1024,
                }),
                mcpg_plugin_protocol::noop_backend_host(),
            )
            .await
            .unwrap();

        let err = plugin
            .execute(
                "slow",
                BackendRequest {
                    payload: vec![],
                    headers: vec![],
                    request_id: "r1".into(),
                    session_id: None,
                    identity: None,
                    idempotency: None,
                },
            )
            .await
            .unwrap_err();
        // No responders → may surface as Transport or Timeout depending on
        // the NATS server state. Both are acceptable.
        assert!(matches!(
            err,
            BackendError::Timeout { .. } | BackendError::Transport { .. }
        ));
        server.kill().ok();
        server.wait().ok();
    }

    /// When the gateway threads an `IdempotencyHint` into
    /// `BackendRequest.idempotency`, the outbound NATS request
    /// must carry `idempotency-key` and
    /// `idempotency-scope-hash` headers (lowercase, ecosystem
    /// convention). NATS headers are case-sensitive — the casing
    /// matters and must match what consumer-side dedupe code
    /// looks for.
    #[tokio::test]
    async fn outbound_request_carries_idempotency_headers() {
        let Some((mut server, port)) = start_nats_server() else {
            return;
        };
        let url = format!("nats://127.0.0.1:{port}");
        let client = connect(&url, None).await.unwrap();
        let plugin = NatsBackendPlugin::new(client);

        plugin
            .register_profile(
                "echo-idem",
                &serde_json::json!({
                    "subject": "mcpg.exec.request.tools.echo_idem",
                    "timeout_ms": 15000,
                    "max_response_bytes": 65536,
                }),
                mcpg_plugin_protocol::noop_backend_host(),
            )
            .await
            .unwrap();

        // Worker subscribes and reflects the received message
        // headers into the response payload (JSON-encoded) so the
        // assertion can inspect what landed on the broker.
        let worker = async_nats::connect(&url).await.unwrap();
        let mut sub = worker
            .subscribe("mcpg.exec.request.tools.echo_idem")
            .await
            .unwrap();
        // Flush on the SAME handle that issued the SUB, and before it is moved
        // into the task. Ordering holds within one client handle; a clone is a
        // separate sender, so a PING sent through it can reach the server
        // ahead of the SUB and the PONG then proves nothing. That is what made
        // this test fail with `no responders` while its sleeping sibling
        // passed.
        worker.flush().await.unwrap();
        tokio::spawn(async move {
            if let Some(msg) = sub.next().await
                && let Some(reply) = msg.reply
            {
                let mut headers = serde_json::Map::new();
                let saw_msg_id = msg
                    .headers
                    .as_ref()
                    .and_then(|h| h.get("Nats-Msg-Id"))
                    .is_some();
                if let Some(h) = msg.headers.as_ref() {
                    if let Some(v) = h.get("idempotency-key") {
                        headers.insert(
                            "idempotency-key".into(),
                            serde_json::Value::String(v.to_string()),
                        );
                    }
                    if let Some(v) = h.get("idempotency-scope-hash") {
                        headers.insert(
                            "idempotency-scope-hash".into(),
                            serde_json::Value::String(v.to_string()),
                        );
                    }
                }
                let body = serde_json::json!({
                    "headers": headers,
                    "saw_nats_msg_id": saw_msg_id,
                });
                worker
                    .publish(reply, bytes::Bytes::from(body.to_string()))
                    .await
                    .ok();
            }
        });

        let resp = plugin
            .execute(
                "echo-idem",
                BackendRequest {
                    payload: b"{}".to_vec(),
                    headers: vec![],
                    request_id: "r1".into(),
                    session_id: None,
                    identity: None,
                    idempotency: Some(mcpg_plugin_protocol::IdempotencyHint {
                        key: "idem-test-key".to_owned(),
                        scope_hash: "deadbeefdeadbeefdeadbeefdeadbeef".to_owned(),
                    }),
                },
            )
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&resp.payload).unwrap();
        assert_eq!(
            body["headers"]["idempotency-key"], "idem-test-key",
            "outbound NATS request must carry idempotency-key; got {body}"
        );
        assert_eq!(
            body["headers"]["idempotency-scope-hash"], "deadbeefdeadbeefdeadbeefdeadbeef",
            "outbound NATS request must carry idempotency-scope-hash; got {body}"
        );
        assert_eq!(
            body["saw_nats_msg_id"], false,
            "core-NATS publish must NOT auto-set Nats-Msg-Id (JetStream-specific opt-in); got {body}"
        );

        server.kill().ok();
        server.wait().ok();
    }

    #[tokio::test]
    async fn watch_plugin_emits_on_message() {
        let Some((mut server, port)) = start_nats_server() else {
            return;
        };
        let url = format!("nats://127.0.0.1:{port}");
        let client = connect(&url, None).await.unwrap();
        let plugin = NatsWatchPlugin::new(client);

        struct CountingSink {
            count: std::sync::atomic::AtomicUsize,
        }
        #[async_trait]
        impl WatchEventSink for CountingSink {
            async fn emit(&self, _event: WatchEvent) {
                self.count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }

        let sink = Arc::new(CountingSink {
            count: std::sync::atomic::AtomicUsize::new(0),
        });
        let handle = plugin
            .watch(
                "mem://res",
                &serde_json::json!({ "subject": "orders.changed" }),
                sink.clone(),
            )
            .await
            .unwrap();

        // Publish a message on the subject
        let pub_client = async_nats::connect(&url).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        pub_client
            .publish("orders.changed", bytes::Bytes::from_static(b"{}"))
            .await
            .unwrap();
        pub_client.flush().await.ok();
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(sink.count.load(std::sync::atomic::Ordering::Relaxed) >= 1);

        handle.cancel().await;
        server.kill().ok();
        server.wait().ok();
    }

    // --- Conformance: the plugin is the single source of truth for its
    // per-binding defaults + value-validation + the transport-only
    // `cred://` reject (the checks that used to live in the gateway's
    // `NatsBackendConfig::validate` / `validate_bindings` nats arm), and
    // it owns the connection-vs-per-binding SPLIT. These run without a
    // live NATS server: spec value-validation runs to completion BEFORE
    // any client is built, so a rejected spec surfaces `InvalidSpec`
    // regardless of broker reachability. ---

    /// Omitting `timeout_ms` / `max_response_bytes` resolves to the same
    /// defaults the gateway binding applied (2000ms / 64 KiB) — the
    /// per-binding default is materialized by the plugin, not the gateway.
    #[test]
    fn per_binding_spec_applies_gateway_defaults() {
        let spec: NatsBackendSpec =
            serde_json::from_value(serde_json::json!({ "subject": "rpc.echo" }))
                .expect("minimal per-binding spec deserializes");
        assert_eq!(
            spec.timeout_ms, 2_000,
            "timeout_ms defaults to 2000 (gateway default_binding_timeout_ms)"
        );
        assert_eq!(
            spec.max_response_bytes, 65_536,
            "max_response_bytes defaults to 64 KiB (gateway default_nats_max_response_bytes)"
        );
        // Connection fields are NOT part of the per-binding spec — they
        // come from `plugins[].config` (the split). An omitted url/creds
        // on the per-binding spec is the common case.
        assert_eq!(spec.url, None);
        assert_eq!(spec.credentials_path, None);
        assert_eq!(spec.auth_token, None);
    }

    /// The connection-vs-per-binding SPLIT resolves correctly: CONNECTION
    /// fields (`url`, `credentials_path`) are sourced from the
    /// `plugins[].config` block the host passes to the cdylib factory;
    /// PER-BINDING fields (`subject`, `timeout_ms`, …) are sourced from the
    /// `register_profile` spec. The two seams are independent.
    #[test]
    fn connection_vs_per_binding_split_resolves() {
        // CONNECTION side: from plugins[].config.
        let backend = NatsBackendPlugin::from_config_json(
            r#"{"url":"nats://broker:4222","credentials_path":"/etc/nats.creds"}"#,
        );
        assert_eq!(backend.conn_url.as_deref(), Some("nats://broker:4222"));
        assert_eq!(backend.conn_creds.as_deref(), Some("/etc/nats.creds"));

        // PER-BINDING side: from the register_profile spec. The spec
        // carries NO connection url/creds (those live on the plugin
        // config), only the binding's routing + budget facts.
        let spec: NatsBackendSpec = serde_json::from_value(serde_json::json!({
            "subject": "rpc.orders",
            "timeout_ms": 1_500,
            "max_response_bytes": 4_096,
        }))
        .expect("per-binding spec deserializes");
        assert_eq!(spec.subject, "rpc.orders");
        assert_eq!(spec.timeout_ms, 1_500);
        assert_eq!(spec.max_response_bytes, 4_096);
        assert_eq!(
            spec.url, None,
            "connection url is not a per-binding field (the split)"
        );
    }

    /// Bad spec values are rejected as `InvalidSpec` — value-validation
    /// moved from the gateway's `NatsBackendConfig::validate`. No broker
    /// needed: validation precedes the client build.
    #[tokio::test]
    async fn register_rejects_bad_values() {
        let plugin = NatsBackendPlugin::from_config_json("");
        for bad in [
            serde_json::json!({ "subject": "" }),
            serde_json::json!({ "subject": "has space" }),
            serde_json::json!({ "subject": "ok", "timeout_ms": 0 }),
            serde_json::json!({ "subject": "ok", "max_response_bytes": 0 }),
        ] {
            let err = plugin
                .register_profile("t", &bad, mcpg_plugin_protocol::noop_backend_host())
                .await
                .expect_err("should reject bad value");
            assert!(
                matches!(err, BackendError::InvalidSpec { .. }),
                "expected InvalidSpec, got {err:?} for {bad}"
            );
        }
    }

    /// A bare `cred://` ref in the transport-only `subject` field is
    /// rejected — the subject is a plaintext routing fact published on the
    /// wire, never a credential carrier (it is never offered to
    /// `host.resolve_credentials`), so a `cred://` there would leak a
    /// resolved secret as the subject name. The credential-bearing
    /// `url` / `credentials_path` / `auth_token` fields are NOT rejected:
    /// they accept `${cred://…}` tokens for the per-caller cred path.
    #[tokio::test]
    async fn register_rejects_cred_in_transport_only_subject() {
        let plugin = NatsBackendPlugin::from_config_json("");
        let err = plugin
            .register_profile(
                "t",
                &serde_json::json!({ "subject": "cred://vault/subject" }),
                mcpg_plugin_protocol::noop_backend_host(),
            )
            .await
            .expect_err("should reject cred:// in transport-only subject");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }
}
