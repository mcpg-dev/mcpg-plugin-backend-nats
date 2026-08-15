# NATS Binding — `dev.mcpg.backend.nats`

> class `backend` · `native` · package `mcpg-plugin-backend-nats` · artifact `libmcpg_plugin_backend_nats.so` · Apache-2.0

Dispatches MCP tool calls as NATS request/reply: the call arguments are
published to an operator-fixed subject, and the reply that arrives on the
auto-generated inbox becomes the tool result. The same artifact also ships a
watch strategy that subscribes to a subject and turns every message on it into a
`notifications/resources/updated` for subscribed sessions. Reach for it when the
system behind a tool is already a NATS responder, or when you want subject-based
routing instead of a point-to-point HTTP call — and so the gateway binary itself
carries no NATS client.

## What it does
- Publishes the tool arguments to `subject` and waits for the reply, bounded by
  `timeout_ms`; a timeout is reported as a distinct error from a transport
  failure.
- Truncates a reply larger than `max_response_bytes` and flags the result as
  truncated rather than returning an unbounded body.
- Forwards inbound request headers as NATS message headers, so W3C
  `traceparent` / `tracestate` propagate to the responder. A gateway idempotency
  hint travels as the lowercase `idempotency-key` and `idempotency-scope-hash`
  headers; `Nats-Msg-Id` is never set, so JetStream broker-level dedupe stays an
  explicit stream-side choice.
- Bundles a second entity — the `nats_topic` watch strategy, manifest id
  `dev.mcpg.watch.nats_topic` — in the same cdylib, so one `plugins[]` entry
  registers both the binding and the watcher.
- Resolves `${cred://issuer/target}` tokens in `url`, `credentials_path`, and
  `auth_token` per caller, and dispatches over a per-credential client cache.
- Rejects at registration a `subject` that is empty, contains spaces, or carries
  a `cred://` reference, and refuses at dispatch a subject holding the `*` or `>`
  wildcards — the subject is a routing fact, never a credential carrier, and the
  manifest advertises `/subject` as a transport-only field.
- Redacts passwords out of NATS URLs before they reach a log line or an error
  message.
- Declares the `network_outbound` capability; the gateway refuses to load the
  plugin unless the `plugins[]` entry grants it.

## Configuration
Per-call config lives in each binding's `backend: { kind: nats, … }` block; the
plugin itself is loaded from the flat top-level `plugins:` list. Connection
parameters are the exception: the gateway reads `url` and `credentials_path`
off the NATS bindings and injects them into the plugin entry, so the entry needs
no `config:` block of its own — and a `kind: nats` binding with no matching
`plugins[]` row fails the boot with an explicit message. The client is connected
lazily on first use.

```yaml
plugins:
  - id: dev.mcpg.backend.nats
    class: backend
    kind: native
    source:
      path: ./plugins/libmcpg_plugin_backend_nats.so
      # or, platform-agnostic:
      # oci: ghcr.io/mcpg-dev/source-code/plugins/backend-nats:protocol-1
    granted_capabilities:
      - network_outbound

mcp:
  capabilities:
    tools:
      - name: price-quote
        description: Request a quote over NATS.
        backend:
          kind: nats
          url: "nats://nats.internal:4222"
          subject: pricing.quote
          timeout_ms: 2000
          max_response_bytes: 65536
          # credentials_path: /etc/mcpg/nats.creds
```

| Field | Type | Default | Description |
|---|---|---|---|
| `subject` | string | — (required) | Request subject. No spaces, no `*` / `>` wildcards, no `cred://`. |
| `timeout_ms` | u64 | `2000` | Per-call reply deadline. Must be greater than zero. |
| `max_response_bytes` | usize | `65536` | Reply size cap; a larger reply is truncated and flagged. |
| `url` | string | — (required) | Server URL (`nats://…` / `tls://…`). The gateway derives the plugin's connection from the first NATS binding that declares it. |
| `credentials_path` | string | unset | Path to a NATS credentials file. |
| `auth_token` | string | unset | Auth token set on the NATS connection options, so the client re-sends it on every reconnect. |

Because the gateway derives one connection from the NATS bindings, every
`kind: nats` binding in a gateway should declare the same `url` and
`credentials_path`.

## Security
`url`, `credentials_path`, and `auth_token` accept a `${cred://issuer/target}`
token, resolved per caller identity through the gateway's credential issuer at
dispatch time. Only that exact `${…}` form resolves — a bare `cred://…` is data,
travels to NATS verbatim, and never reaches the resolver, so a caller cannot
smuggle a credential reference through a tool argument. The snapshot handed to
the resolver is built solely from the operator's own config literals; request
arguments and headers travel on a separate path and are never offered to it.

## Connection pooling
A binding whose spec carries no credential token connects once at registration
using its own declared `url`, or falls back to the plugin's lazily-connected
shared client when the spec declares none. A binding that does carry a
credential token instead gets a client per resolved-credential bundle, keyed on
a BLAKE3 digest of the resolved `url` / `credentials_path` / `auth_token`
values, from a registry bounded at 256 entries with a 15-minute idle eviction and
a sweeper that runs every 60 seconds. A credential-revocation event evicts every
client built from the revoked `(plugin_id, target)` pair, and a secret-rotation
event evicts the clients built from the rotated secret, so a revoked or rotated
credential does not keep a live connection alive. A binding that puts a token in
`credentials_path` or `auth_token` must also declare `url` — the per-credential
path needs an explicit connect URL.

## Change-watching
The bundled `nats_topic` strategy subscribes to a subject and emits a change
event for every message that arrives on it; the payload is not inspected, so any
message means "this resource changed". Attach it to a resource binding's
`watch:` block:

```yaml
mcp:
  capabilities:
    resources:
      - name: catalog.snapshot
        description: The product catalog.
        uri: "catalog://snapshot"
        backend: { kind: nats, url: "nats://nats.internal:4222", subject: catalog.read }
        watch:
          strategy:
            type: nats_topic
            subject: catalog.changed
```

`subject` is the only field the watch spec accepts, it must be non-empty, and
unknown fields are rejected. If the subscription stream ends the watch loop
terminates rather than spinning, and the gateway re-establishes the watch on its
next resolve cycle.

## Observability
Every dispatch runs inside a `nats_binding_execute` span tagged with the plugin
id and binding name, and records `mcpg_nats_binding_calls_total` (labels
`backend`, `outcome`, `error_kind`) plus `mcpg_nats_binding_call_ms` (labels
`backend`, `outcome`). The watcher records `mcpg_nats_watch_subscribes_total`
(label `outcome`), `mcpg_nats_watch_subscribe_ms`, and
`mcpg_nats_watch_events_total`. NATS is a messaging transport rather than a
probe-able endpoint, so the manifest declares no active health probe and health
stays advisory.

## MCP surfaces & composition

### As a pipeline step
`nats` is pipeline-capable. Inside a `kind: pipeline` binding the step's `kind`
names the plugin and every sibling key is the backend spec. `input_transform` is
a raw CEL expression (variables: `arguments`, `steps`, `context`, `tool_name`)
that shapes what the step publishes; without it the step publishes the tool
arguments unchanged.

```yaml
      backend:
        kind: pipeline
        steps:
          - id: quote
            kind: nats
            url: "nats://nats.internal:4222"
            subject: pricing.quote
            timeout_ms: 2000
            input_transform: "{ 'sku': arguments.sku }"
```

### As a resource
Place the binding under `mcp.capabilities.resources[]`. The responder's reply
must be a JSON body carrying an MCP `contents` array, which becomes the
`resources/read` result.

### As a prompt
Under `mcp.capabilities.prompts[]` the reply must instead carry a `messages`
array, validated against the MCP content-block shape.

### As a child tool
A `kind: nats` tool binding is eligible as an LLM child tool — name it in an LLM
binding's `tools.allowed` list and the model can invoke it during its reasoning
loop.

### Schemas & annotations
The plugin derives no schema from the subject. Declare `input_schema`,
`output_schema`, and `annotations` on the capability entry itself.

## Build
Default feature set is OFF (avoids `mcpg_plugin_register` linker
collisions in the workspace build); opt in to the cdylib:

```bash
cargo build -p mcpg-plugin-backend-nats --features cdylib-export --release   # → target/release/libmcpg_plugin_backend_nats.so
```

## Testing
Much of the suite spawns a real `nats-server` on a free port and drives request
/ reply and subject subscription against it, so that binary must be on `PATH`:

```bash
cargo test -p mcpg-plugin-backend-nats
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Backend binding reference: <https://mcpg.dev/docs/reference/backends>
- Plugin classes and the plugin ABI: <https://mcpg.dev/docs/plugins/plugins-and-protocol>
- The other messaging backend: `libs/plugins/backend/kafka`
