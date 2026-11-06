# Threat model (v0.1)

| Threat | Present control | Remaining risk |
|---|---|---|
| Agent instructed to execute shell | Unknown tools deny + explicit deny rules | Direct unwrapped shell access bypasses gateway |
| Prompt injection triggers cross-tool exfiltration | Host-side allowlists + approval for external sends | Allowed handler can misuse data; content-based DLP absent |
| Agent asks for private files | Canonical path checks under configured roots | Symlink races; handler must enforce secure open |
| Rogue server modifies tool schema | Optional hash pin validated from trusted registry | Host must supply authenticated schema, recheck per execution |
| Unauthorized approval / token replay | HMAC + call fingerprint + TTL + SQLite one-use UPDATE | Stolen token can be used once before legitimate consumer; isolate trusted host |
| Tampered local logs | HMAC chain | Key compromise, deletion, concurrent writers; external checkpoint needed |
| Secrets in tool args | Sensitive key + common token-pattern rejection | Encoded, chunked, novel secrets missed; additional DLP needed |
| SSRF / DNS rebinding | HTTPS + exact destination hostname allowlists | Network-layer DNS, IP, redirect controls required |
| Malicious package / build | No runtime dependencies; minimal CI permissions | CI actions use immutable SHA pins; review and refresh them before release |

Trust boundary: the agent provides `tool` and `arguments`; the **trusted host** supplies `principal`, registered tool identity/schema, active policy, approvals, and sandboxed handler. Any model-generated field treated as trusted identity is a host integration bug.

This component authorizes an initial call. It does not inspect downstream tool results, execute OS sandboxing, or enforce data-flow semantics. Design future versions for egress sink labels and per-field redaction without claiming comprehensive protection.
