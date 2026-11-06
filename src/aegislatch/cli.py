"""No execution: inspect policy decisions and compute pinned tool-schema hashes."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from .core import Policy, ToolCall, digest, load_json_strict


def main() -> int:
    p = argparse.ArgumentParser(prog="aegislatch")
    commands = p.add_subparsers(dest="cmd", required=True)
    check = commands.add_parser("check", help="Evaluate a call without performing it")
    check.add_argument("policy")
    check.add_argument("call")
    pin = commands.add_parser("schema-hash", help="Hash a reviewed tool definition")
    pin.add_argument("schema")
    args = p.parse_args()
    try:
        if args.cmd == "schema-hash":
            schema = load_json_strict(Path(args.schema).read_text(encoding="utf-8"))
            print(digest(schema))
            return 0
        data = load_json_strict(Path(args.call).read_text(encoding="utf-8"))
        call = ToolCall(**data)
        decision = Policy.from_file(args.policy).evaluate(call)
        print(json.dumps({"status": decision.status, "reason": decision.reason,
                          "rule_id": decision.rule_id}, sort_keys=True))
        return 0 if decision.allowed else 2
    except (OSError, ValueError, TypeError) as exc:
        print(json.dumps({"status": "deny", "reason": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
