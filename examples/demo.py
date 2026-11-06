"""Execute a trusted handler with a safe sample file; no network involved."""
from pathlib import Path
from aegislatch import Gateway, Policy, ToolCall

here = Path(__file__).resolve().parent
sample = (here / "workspace" / "hello.txt").resolve()
policy = Policy.from_file(here / "policy.json")
call = ToolCall(principal="demo-user", server="local-demo", tool="read_note",
                arguments={"path": str(sample)})

def trusted_read_note(path: str) -> str:
    # Defense in depth: a production handler should re-check with a sandboxed
    # file-descriptor-based mechanism to prevent link swaps/TOCTOU.
    return Path(path).read_text(encoding="utf-8")

print(Gateway(policy).execute(call, trusted_read_note).strip())
