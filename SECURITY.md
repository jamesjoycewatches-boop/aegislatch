# Security policy

This project is security-sensitive and is **not yet independently audited**.

## Vulnerability reporting
Do **not** open public issues containing exploits or user secrets. Before public release, the maintainer should enable GitHub private vulnerability reporting and publish a secure contact channel. Until then, report privately to the repository maintainer.

## Security properties
- Explicit per-principal, per-server, per-tool rules; unknown calls fail closed.
- Structured resource checks for paths and HTTPS destination names.
- Optional independent one-use, action-bound, short-lived human-approval tickets.
- Optional HMAC audit chain with no raw tool arguments in log events.
- No telemetry or runtime network calls inside this package; no runtime dependencies.

## Non-guarantees
- Not a sandbox, kernel enforcement layer, firewall, general PII scanner, or prompt-injection detector.
- URL checks do not prevent DNS rebinding, redirect attacks, proxy bypasses, or SSRF at the network layer. Validate destination IP and redirects in the actual HTTP client; enforce egress at infrastructure layer.
- Path checks are susceptible to TOCTOU races if untrusted code can mutate symlinks. Use safe filesystem primitives / OS isolation in handlers.
- Approval issuers and signing secrets **must not** be accessible to the LLM/agent. Key compromise permits forgery.
- The local HMAC audit chain is tamper-evident only if the key and log are protected. File removal is not detectable without external checkpoints. Single writer per log.
- Structured checks cannot stop a tool handler that independently accesses unauthorized resources or agent calls bypassing the Gateway.
- Approval tickets are local single-use with SQLite transactions; production distributed deployments need a security review of key storage, DB permissions, and resilience.
- Secret pattern checks are best effort and do not detect all encoded or novel credentials.

## Safe deployment requirements
1. Authenticate the principal in trusted application code; never accept model-authored identity.
2. Register reviewed tool schemas and pin their canonical hashes for high-impact tools.
3. Give the model only Gateway-wrapped tools. Remove direct network, file and shell access, and sandbox handlers.
4. Keep the approval issuer, database, audit and HMAC keys in a separate trusted host environment.
5. Configure process-level disk permissions, resource limits, network egress allowlists, redirect controls and DNS/IP validation.
6. Require human review for any destructive, financial, sensitive-data, or external message operation.
7. Run static analysis, secret scanning, threat simulations, supply-chain review, and an independent security audit before making broad security claims.