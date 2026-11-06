"""Fail-closed, side-effect-free policy evaluation for AI tool calls."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping
import hmac
import ipaddress
import json
import os
import re
from urllib.parse import urlsplit


class PolicyError(ValueError):
    """A policy is invalid; it must never silently degrade to allow."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return sha256(canonical_json(value)).hexdigest()


@dataclass(frozen=True)
class ToolCall:
    # This principal MUST come from the host's authenticated session, never the LLM.
    principal: str
    server: str
    tool: str
    arguments: dict[str, Any]

    def fingerprint(self) -> str:
        return digest({"principal": self.principal, "server": self.server,
                       "tool": self.tool, "arguments": self.arguments})


@dataclass(frozen=True)
class Decision:
    status: str  # allow, deny, review
    reason: str
    rule_id: str | None = None

    @property
    def allowed(self) -> bool:
        return self.status == "allow"


@dataclass(frozen=True)
class Rule:
    id: str
    principal: str
    server: str
    tool: str
    effect: str
    resource: Mapping[str, Any]
    schema_sha256: str | None = None


# Pattern matches are advisory leak prevention, not comprehensive DLP.
_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\b(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bBearer\s+\S{16,}\b", re.IGNORECASE),
)
_SENSITIVE_KEYS = frozenset(("password", "passphrase", "secret", "api_key", "apikey",
                             "access_token", "refresh_token", "private_key", "authorization"))


def _has_sensitive_data(value: Any, depth: int = 0) -> bool:
    if depth > 16:
        return True
    if isinstance(value, dict):
        for key, val in value.items():
            if not isinstance(key, str):
                return True
            if key.casefold() in _SENSITIVE_KEYS and val not in (None, ""):
                return True
            if _has_sensitive_data(val, depth + 1):
                return True
    elif isinstance(value, list):
        return any(_has_sensitive_data(v, depth + 1) for v in value)
    elif isinstance(value, str):
        return any(p.search(value) for p in _SECRET_PATTERNS)
    return False


def _inside(path: str, root: str) -> bool:
    try:
        return os.path.commonpath((path, root)) == root
    except ValueError:
        return False


def _validate_resource(rule: Rule, args: dict[str, Any]) -> str | None:
    r = rule.resource
    kind = r["kind"]
    if kind == "none":
        return None
    value = args.get(r["arg"])
    if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(c) < 32 for c in value):
        return "resource argument missing or invalid"
    if kind == "file":
        if not os.path.isabs(value):
            return "file path must be absolute"
        real = os.path.realpath(value)
        if not any(_inside(real, root) for root in r["roots"]):
            return "file path outside permitted roots"
        return None
    if kind == "url":
        try:
            parsed = urlsplit(value)
            host = parsed.hostname
            port = parsed.port
        except ValueError:
            return "invalid URL"
        if parsed.scheme != "https" or not host or parsed.username is not None or parsed.password is not None:
            return "URL must use HTTPS without embedded credentials"
        if port not in (None, 443) or parsed.fragment or "\\" in value:
            return "URL includes forbidden port, fragment, or escape"
        if host.endswith(".") or host not in r["hosts"]:
            return "destination not explicitly allowed"
        try:
            ipaddress.ip_address(host)
            return "IP literals are not allowed"
        except ValueError:
            pass
        # The caller/executor must validate DNS, redirects and network egress too.
        query = parsed.query.lower()
        if re.search(r"(?:^|&)(?:api[_-]?key|token|secret|password|access_token)=", query):
            return "credentials in URL query are prohibited"
        return None
    return "unknown resource type"


def _parse_policy(data: Any, base: Path) -> dict[tuple[str, str, str], Rule]:
    if not isinstance(data, dict) or set(data) != {"version", "default", "rules"}:
        raise PolicyError("Policy must contain only version, default, and rules")
    if type(data["version"]) is not int or data["version"] != 1 or data["default"] != "deny" or not isinstance(data["rules"], list):
        raise PolicyError("Only version 1, default-deny policies are supported")
    compiled = {}
    for record in data["rules"]:
        if not isinstance(record, dict):
            raise PolicyError("Rule must be an object")
        required = {"id", "principal", "server", "tool", "effect", "resource"}
        if not required.issubset(record) or set(record) - (required | {"schema_sha256"}):
            raise PolicyError("Unexpected/missing rule fields")
        for field in ("id", "principal", "server", "tool"):
            if not isinstance(record[field], str) or not record[field].strip() or len(record[field]) > 128:
                raise PolicyError(f"Invalid rule {field}")
        if record["effect"] not in ("allow", "deny", "review"):
            raise PolicyError("Invalid rule effect")
        resource = record["resource"]
        if not isinstance(resource, dict) or resource.get("kind") not in ("none", "file", "url"):
            raise PolicyError("Invalid resource specification")
        kind = resource["kind"]
        if kind == "none":
            if set(resource) != {"kind"}:
                raise PolicyError("No-resource rule has unexpected fields")
        elif kind == "file":
            if set(resource) != {"kind", "arg", "roots"} or not isinstance(resource["roots"], list) or not resource["roots"]:
                raise PolicyError("Invalid file resource")
            if not isinstance(resource["arg"], str) or not resource["arg"]:
                raise PolicyError("Invalid file argument name")
            roots = []
            for root in resource["roots"]:
                if not isinstance(root, str) or not root or "~" in root or "$" in root:
                    raise PolicyError("Invalid file root")
                roots.append(os.path.realpath(str(base / root)))
            resource = {"kind": "file", "arg": resource["arg"], "roots": roots}
        elif kind == "url":
            if set(resource) != {"kind", "arg", "hosts"} or not isinstance(resource["hosts"], list) or not resource["hosts"]:
                raise PolicyError("Invalid URL resource")
            if not isinstance(resource["arg"], str) or not resource["arg"]:
                raise PolicyError("Invalid URL argument name")
            hosts = []
            for host in resource["hosts"]:
                if (not isinstance(host, str) or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host)
                    or "." not in host or ".." in host or host.startswith("xn--")):
                    raise PolicyError("Invalid allowed hostname")
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    pass
                else:
                    raise PolicyError("IP literal hosts are not supported")
                hosts.append(host)
            resource = {"kind": "url", "arg": resource["arg"], "hosts": tuple(hosts)}
        pin = record.get("schema_sha256")
        if pin is not None and (not isinstance(pin, str) or not re.fullmatch(r"[a-f0-9]{64}", pin)):
            raise PolicyError("Invalid schema pin")
        rule = Rule(record["id"], record["principal"], record["server"],
                    record["tool"], record["effect"], resource, pin)
        key = (rule.principal, rule.server, rule.tool)
        if key in compiled:
            raise PolicyError("Overlapping rules are forbidden")
        compiled[key] = rule
    return compiled


class Policy:
    """Policy evaluation does no filesystem/network execution on behalf of the agent."""
    def __init__(self, data: dict[str, Any], base_dir: str | Path = ".") -> None:
        self._rules = _parse_policy(data, Path(base_dir).resolve())

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        path = Path(path).resolve()
        return cls(load_json_strict(path.read_text(encoding="utf-8")), path.parent)

    def evaluate(self, call: ToolCall, trusted_schema: dict[str, Any] | None = None) -> Decision:
        if not isinstance(call.arguments, dict) or any(not isinstance(k, str) for k in call.arguments):
            return Decision("deny", "arguments must be a JSON object")
        if not all(isinstance(x, str) and x for x in (call.principal, call.server, call.tool)):
            return Decision("deny", "invalid caller or tool identity")
        try:
            size = len(canonical_json(call.arguments))
        except (ValueError, TypeError, OverflowError, RecursionError):
            return Decision("deny", "arguments must be bounded valid JSON")
        if size > 16384:
            return Decision("deny", "arguments exceed 16 KiB limit")
        if _has_sensitive_data(call.arguments):
            return Decision("deny", "potential secret in tool arguments")
        rule = self._rules.get((call.principal, call.server, call.tool))
        if rule is None:
            return Decision("deny", "no matching rule: default deny")
        if rule.schema_sha256 is not None:
            if trusted_schema is None or not hmac.compare_digest(digest(trusted_schema), rule.schema_sha256):
                return Decision("deny", "trusted tool schema hash mismatch", rule.id)
        if rule.effect == "deny":
            return Decision("deny", "explicit policy denial", rule.id)
        violation = _validate_resource(rule, call.arguments)
        if violation:
            return Decision("deny", violation, rule.id)
        return Decision(rule.effect, "matched explicit policy rule", rule.id)


def _no_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON key: {key}")
        obj[key] = value
    return obj


def load_json_strict(src: str) -> Any:
    return json.loads(src, object_pairs_hook=_no_duplicate_pairs,
                      parse_constant=lambda c: (_ for _ in ()).throw(ValueError(f"invalid constant: {c}")))
