#!/usr/bin/env python3
"""
fp_common — shared plumbing for the fastpath blackbox toolkit.

Every outbound request in the fastpath tools (fp_fingerprint, fp_diff,
fastpath) MUST go through ``FastpathHTTP`` so that:

  * the hostname is checked against an in-scope allowlist BEFORE any
    packet leaves (deterministic ``ScopeChecker``, not LLM judgment);
  * the request is recorded in the append-only audit log;
  * a shared rate limit / timeout / User-Agent policy applies.

This mirrors the safety posture already used by hunt.py / autopilot:
nothing touches a target without a scope decision and an audit trail.

Authorized testing only. Load the program scope before running.
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

# Repo layout — resolve dirs the same way hunt.py does.
TOOLS_DIR = Path(__file__).resolve().parent
BASE_DIR = TOOLS_DIR.parent

# Make `import memory...` and sibling tools importable when run as a script.
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

RECON_DIR = BASE_DIR / "recon"
FINDINGS_DIR = BASE_DIR / "findings"
STATE_DIR = BASE_DIR / "hunt-memory" / "fastpath"

DEFAULT_UA = (
    "Mozilla/5.0 (compatible; bugbounty-fastpath/1.0; authorized-testing)"
)

# ── Colours / logging (match hunt.py conventions) ────────────────────────────

GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
NC = "\033[0m"

_SYMBOLS = {"ok": "+", "err": "-", "warn": "!", "info": "*", "vuln": "VULN"}
_COLORS = {"ok": GREEN, "err": RED, "warn": YELLOW, "info": CYAN, "vuln": RED}


def log(level: str, msg: str) -> None:
    """Coloured stderr log line (stdout stays clean for machine output)."""
    color = _COLORS.get(level, "")
    sym = _SYMBOLS.get(level, "*")
    print(f"{color}{BOLD}[{sym}]{NC} {msg}", file=sys.stderr)


# ── Scope gate ────────────────────────────────────────────────────────────────

try:
    from tools.scope_checker import ScopeChecker  # type: ignore
except Exception:  # pragma: no cover - fallback when run from tools/
    from scope_checker import ScopeChecker  # type: ignore


class ScopeError(Exception):
    """Raised when a request targets a host outside the authorized scope."""


# ── Audit log (best effort — never block testing if schema import fails) ─────

def _make_audit_log():
    try:
        from memory.audit_log import AuditLog  # type: ignore

        return AuditLog(BASE_DIR / "hunt-memory" / "audit.jsonl")
    except Exception as exc:  # pragma: no cover
        log("warn", f"audit log unavailable ({exc}); continuing without it")
        return None


@dataclass
class HTTPResult:
    """Lightweight view of a response, decoupled from requests internals."""

    url: str
    status: int
    headers: dict[str, str]
    body: str
    elapsed_ms: int
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class FastpathHTTP:
    """Scope-gated, audit-logged HTTP client shared by all fastpath tools."""

    scope: ScopeChecker
    session_id: str = "fastpath"
    timeout: float = 12.0
    rate_limit_per_sec: float = 3.0
    verify_tls: bool = True
    max_body_bytes: int = 2_000_000
    user_agent: str = DEFAULT_UA
    extra_headers: dict[str, str] = field(default_factory=dict)

    _last_request_ts: float = field(default=0.0, init=False, repr=False)
    _session: object | None = field(default=None, init=False, repr=False)
    _audit: object | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        import requests  # local import keeps module importable without requests

        self._session = requests.Session()
        self._session.headers.update({"User-Agent": self.user_agent})
        self._session.headers.update(self.extra_headers)
        self._audit = _make_audit_log()

    # -- internals -----------------------------------------------------------

    def _throttle(self) -> None:
        if self.rate_limit_per_sec <= 0:
            return
        min_gap = 1.0 / self.rate_limit_per_sec
        delta = time.monotonic() - self._last_request_ts
        if delta < min_gap:
            time.sleep(min_gap - delta)
        self._last_request_ts = time.monotonic()

    def _audit_request(self, url: str, method: str, decision: str,
                       status: int | None, error: str | None) -> None:
        if self._audit is None:
            return
        try:
            self._audit.log_request(
                url=url,
                method=method.upper(),
                scope_check=decision,
                response_status=status,
                session_id=self.session_id,
                error=error,
            )
        except Exception as exc:  # pragma: no cover - never fail the hunt on audit
            log("warn", f"audit write failed: {exc}")

    # -- public API ----------------------------------------------------------

    def in_scope(self, url: str) -> bool:
        return self.scope.is_in_scope(url)

    def request(self, method: str, url: str, **kwargs) -> HTTPResult:
        """Perform a scope-checked request. Raises ScopeError if out of scope."""
        if not self.in_scope(url):
            self._audit_request(url, method, "out_of_scope", None, "blocked")
            raise ScopeError(f"out of scope: {urlparse(url).hostname or url}")

        import requests

        self._throttle()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_tls)
        kwargs.setdefault("allow_redirects", True)
        start = time.monotonic()
        try:
            resp = self._session.request(method.upper(), url, **kwargs)
            body = resp.text[: self.max_body_bytes]
            elapsed = int((time.monotonic() - start) * 1000)
            self._audit_request(url, method, "in_scope", resp.status_code, None)
            return HTTPResult(
                url=url,
                status=resp.status_code,
                headers={k: v for k, v in resp.headers.items()},
                body=body,
                elapsed_ms=elapsed,
            )
        except requests.RequestException as exc:
            elapsed = int((time.monotonic() - start) * 1000)
            self._audit_request(url, method, "in_scope", None, str(exc))
            return HTTPResult(url, 0, {}, "", elapsed, error=str(exc))

    def get(self, url: str, **kwargs) -> HTTPResult:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs) -> HTTPResult:
        kwargs.setdefault("allow_redirects", True)
        return self.request("HEAD", url, **kwargs)


def load_scope_from_args(domains: list[str] | None,
                         scope_file: str | None) -> ScopeChecker:
    """Build a ScopeChecker from --scope patterns and/or a --scope-file.

    The scope file is newline-delimited; lines starting with '!' are
    treated as exclusions, '#' lines and blanks are ignored.
    """
    allow: list[str] = list(domains or [])
    deny: list[str] = []
    if scope_file:
        for raw in Path(scope_file).read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("!"):
                deny.append(line[1:].strip())
            else:
                allow.append(line)
    if not allow:
        raise ValueError(
            "no in-scope domains supplied — pass --scope and/or --scope-file"
        )
    return ScopeChecker(domains=allow, excluded_domains=deny)


def ensure_dirs() -> None:
    for d in (RECON_DIR, FINDINGS_DIR, STATE_DIR):
        d.mkdir(parents=True, exist_ok=True)
