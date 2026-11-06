# AegisLatch

**A default-deny policy gate for AI-agent tool calls — local-first, privacy-conscious, transparent.**

> **Status:** v0.1 public developer preview. Not production-certified; no claim of complete prompt-injection or data-leak prevention.

AI agents can read files, send messages, call third-party APIs and trigger code. AegisLatch helps developers put a deterministic authorization boundary between a model's proposed action and a trusted tool handler. It is vendor-neutral; no model API key required.

## Capabilities

- **Default deny.** Only exact authenticated principal / server / tool combinations listed in a local JSON policy may be considered.
- **Resource-aware.** Absolute filesystem path containment checks and exact HTTPS destination-host allowlists. Unsafe URLs, secret-bearing arguments, and oversized JSON are denied.
- **Human review.** Risky actions may be labeled `review`; a separate trusted human component can issue a short-lived one-use ticket bound to the exact proposed action.
- **Tool-schema pinning.** Optional SHA-256 of a trusted, reviewed canonical JSON tool definition.
- **Audit option.** Local HMAC-chained log of decision, rule and call hash without raw payloads; no telemetry.
- **Zero runtime dependencies.** Standard-library Python 3.11+; no external network calls from the package.

## Architecture

```text
untrusted model output (tool + args)
              │
              ▼
 trusted host injects user identity + registered tool/schema
              │
              ▼
      AegisLatch Policy
    ┌─────────┼──────────┐
   DENY      REVIEW     ALLOW
    │     one-time human   │
    │       approval       │
    └─────────┼───────────┘
              ▼
  sandboxed trusted handler + independent OS/network policy
```

AegisLatch does not run tools by itself and does not promise that an allowed handler is safe. The host must make the gateway the **only** execution route, with independent filesystem/network enforcement.

## Quick start

```bash
python -m pip install -e .
python examples/demo.py
python -m unittest discover -s tests -v
python -m aegislatch check examples/policy.json examples/blocked-call.json
```

The last command should return `deny` and exit code `2`.

### Embed in a trusted application

```python
from aegislatch import Policy, Gateway, ToolCall

policy = Policy.from_file("examples/policy.json")
call = ToolCall(
    principal="demo-user",  # authenticated and injected by trusted host
    server="local-demo", tool="read_note",
    arguments={"path": "/absolute/path/to/aegislatch/examples/workspace/hello.txt"},
)

# Register trusted_read_note inside a sandbox. Never expose raw handlers to LLMs.
result = Gateway(policy).execute(call, trusted_read_note)
```

For an exact reproducible example, run `examples/demo.py`; it resolves the test path automatically.

### Review decision and signed approval

```python
from aegislatch import Policy, ToolCall, ApprovalAuthority, Gateway

policy = Policy.from_file("examples/policy.json")
call = ToolCall("demo-user", "web-demo", "send_payload",
                {"url": "https://api.example.com/submit", "payload": "public demo only"})
decision = policy.evaluate(call)  # status == 'review'

# HUMAN-ONLY SERVICE -- not exposed to agent/model. Store signing key securely.
# authority = ApprovalAuthority("/protected/private/approvals.db", secret_key_32_bytes)
# ticket = authority.issue_after_human_review(call, decision, approver="verified-human")
# result = Gateway(policy, approvals=authority).execute(call, trusted_handler, approval_ticket=ticket)
```

The issuer method must be invoked only after real user-facing review of the **full proposed arguments**; the example intentionally does not create a remote HTTP client or auto-approval channel.

## Documentation

- [Local security audit and limitations](docs/SECURITY_AUDIT.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Security boundary and non-guarantees](SECURITY.md)
- [Public release checklist](docs/RELEASE_CHECKLIST.md)
- [Contributing](CONTRIBUTING.md)

## Roadmap

v0.2: adapter layer for MCP servers (authenticated tool registry, full schema pinning, approval UI); safe file-descriptor API; network egress enforcement integration; immutable audit checkpoints; property-based adversarial tests; SBOM and signed releases. The current package is a library, **not** an MCP server or MCP proxy.

## Why this exists

Aligned with OWASP's AI-agent guidance on least privilege, trusted tool authorization and human-in-the-loop controls. It is a practical building block, not a substitute for existing security architecture.

- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
- [OWASP GenAI LLM Top 10 2026](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10)

## License

MIT. No external service required. No analytics or telemetry. Maintainer attribution can be added in a later release at the repository owner's request.