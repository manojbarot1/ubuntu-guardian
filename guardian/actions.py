"""User-approved actions. Nothing here runs without an explicit preview -> confirm cycle.

Flow:
  preview(request)  -> plan with impact, preconditions and a short-lived signed token
  execute(token, confirm_text) -> re-checks preconditions, records before/after state in the
                                  append-only audit log together with rollback instructions

Service changes go through the root helper (executor/guardian-exec) over a Unix socket; it has its
own allowlist so a compromised dashboard still cannot run arbitrary commands.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import time

from . import config as C
from . import duplicates, intel, services_kb
from .util import docker_api, run

EXEC_SOCKET = "/run/guardian-exec.sock"
TOKEN_TTL = 300
SERVICE_VERBS = {"start", "stop", "restart", "enable", "disable"}
CONTAINER_VERBS = {"start", "stop", "restart"}
CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_KEY = secrets.token_bytes(32)


class ActionError(Exception):
    pass


def _sign(plan: dict) -> str:
    body = base64.urlsafe_b64encode(json.dumps(plan, sort_keys=True).encode()).decode()
    mac = hmac.new(_KEY, body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{mac}"


def _unsign(token: str) -> dict:
    try:
        body, mac = token.rsplit(".", 1)
    except ValueError:
        raise ActionError("malformed token")
    if not hmac.compare_digest(mac, hmac.new(_KEY, body.encode(), hashlib.sha256).hexdigest()):
        raise ActionError("invalid token")
    plan = json.loads(base64.urlsafe_b64decode(body))
    if time.time() - plan["issued"] > TOKEN_TTL:
        raise ActionError("confirmation expired; preview again")
    return plan


def executor_available() -> bool:
    return os.path.exists(EXEC_SOCKET)


def _exec_call(verb: str, unit: str) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(90)
    try:
        s.connect(EXEC_SOCKET)
        s.sendall(json.dumps({"verb": verb, "unit": unit}).encode() + b"\n")
        data = b""
        while not data.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    finally:
        s.close()
    return json.loads(data or b'{"ok": false, "error": "no reply from executor"}')


def _unit_state(unit: str) -> dict:
    p = intel.show(unit)
    return {k: p.get(k) for k in ("ActiveState", "SubState", "UnitFileState")}


def _container_state(name: str) -> dict:
    d = docker_api(f"/containers/{name}/json")
    return {"status": d["State"]["Status"], "health": (d["State"].get("Health") or {}).get("Status"),
            "restart_count": d.get("RestartCount", 0)}


class Actions:
    def __init__(self, cfg, db, gov):
        self.cfg, self.db, self.gov = cfg, db, gov
        self._used: dict[str, float] = {}  # nonce -> issued; confirmation tokens are single-use

    # ------------------------------------------------------------------ preview
    def preview(self, req: dict) -> dict:
        kind = req.get("type")
        if kind == "service":
            plan = self._preview_service(req.get("verb", ""), req.get("target", ""))
        elif kind == "service_rollback":
            plan = self._preview_rollback(int(req.get("audit_id", 0)))
        elif kind == "container":
            plan = self._preview_container(req.get("verb", ""), req.get("target", ""))
        elif kind == "backup_run":
            plan = self._preview_backup()
        elif kind in ("quarantine", "restore", "purge"):
            plan = self._preview_files(kind, int(req.get("scan_id", 0)), list(req.get("paths") or []))
        else:
            raise ActionError("unknown action type")
        plan["issued"] = time.time()
        plan["nonce"] = secrets.token_hex(8)
        plan["blocked"] = [p for p in plan["preconditions"] if not p["ok"] and p.get("blocking", True)]
        plan["token"] = None if plan["blocked"] else _sign({k: v for k, v in plan.items() if k != "token"})
        return plan

    def _preview_service(self, verb: str, unit: str) -> dict:
        if verb not in SERVICE_VERBS:
            raise ActionError("unsupported verb")
        if not intel.valid_unit(unit):
            raise ActionError("invalid unit name")
        d = intel.detail(unit, self.cfg, None, None)
        kb = d["kb"]
        risk = kb.get("risk", "unknown")
        pre = [
            {"check": "Root helper installed", "ok": executor_available(),
             "detail": "Run: " + C.EXECUTOR_INSTALL},
            {"check": "Not a protected unit", "ok": not d["protected"],
             "detail": "Guardian refuses to change critical/protected services."},
            {"check": f"'{verb}' makes sense in the current state", "ok": verb in d["allowed_actions"],
             "detail": f"Current: {d['props'].get('ActiveState')}/{d['props'].get('UnitFileState')}"},
        ]
        if d["immich_related"] and verb in ("stop", "restart", "disable"):
            pre.append({"check": "Immich impact", "ok": False, "blocking": False,
                        "detail": "This service supports Docker/Immich. Photo backup from phones will be interrupted."})
        if self.gov.immich_busy and verb in ("stop", "restart"):
            pre.append({"check": "Immich is idle", "ok": False, "blocking": False,
                        "detail": "Immich is processing right now. Consider waiting."})
        strong = risk in ("high", "medium", "unknown") or verb == "disable" or d["immich_related"]
        impact = d["consequences"]["disable" if verb == "disable" else "stop"] if verb in ("stop", "disable", "restart") \
            else "The service will start/enable. Check its resource use afterwards."
        rollback = {"stop": "start", "start": "stop", "disable": "enable", "enable": "disable", "restart": None}[verb]
        return {
            "type": "service", "verb": verb, "target": unit,
            "summary": f"{verb.capitalize()} {unit}" + (" (and keep it from starting at boot)" if verb == "disable" else ""),
            "impact": impact, "risk": risk, "preconditions": pre,
            "confirm": {"level": "type", "text": unit} if strong else {"level": "click"},
            "before": _unit_state(unit),
            "rollback": f"{rollback} {unit}" if rollback else "Restart has no rollback; the service keeps its enabled state.",
        }

    def _preview_rollback(self, audit_id: int) -> dict:
        row = self.db.one("SELECT * FROM audit_log WHERE id=? AND action LIKE 'service.%' AND status='done'", (audit_id,))
        if not row:
            raise ActionError("no completed service action with that id")
        before = json.loads(row["before_state"] or "{}")
        unit = row["target"]
        cur = _unit_state(unit)
        verbs = []
        if before.get("UnitFileState") in ("enabled", "disabled") and cur.get("UnitFileState") != before["UnitFileState"]:
            verbs.append("enable" if before["UnitFileState"] == "enabled" else "disable")
        if before.get("ActiveState") in ("active", "inactive") and cur.get("ActiveState") != before["ActiveState"]:
            verbs.append("start" if before["ActiveState"] == "active" else "stop")
        plan = {
            "type": "service_rollback", "target": unit, "audit_id": audit_id, "verbs": verbs,
            "summary": f"Restore {unit} to its state before action #{audit_id}: "
                       + (", ".join(verbs) if verbs else "already in that state"),
            "impact": f"Before: {before}. Now: {cur}.", "risk": services_kb.lookup(unit).get("risk"),
            "preconditions": [{"check": "Root helper installed", "ok": executor_available(),
                               "detail": "Run: " + C.EXECUTOR_INSTALL},
                              {"check": "Something to restore", "ok": bool(verbs), "detail": "Current state already matches."}],
            "confirm": {"level": "click"}, "before": cur, "rollback": "Run the original action again.",
        }
        return plan

    def _preview_container(self, verb: str, name: str) -> dict:
        if verb not in CONTAINER_VERBS or not CONTAINER_RE.match(name):
            raise ActionError("invalid container action")
        try:
            before = _container_state(name)
        except Exception:
            raise ActionError(f"container {name} not found")
        immich = name in self.cfg["immich"]["containers"]
        pre = [{"check": f"'{verb}' makes sense", "ok": (verb == "start") != (before["status"] == "running"),
                "detail": f"Container is {before['status']}"}]
        if immich and verb != "start":
            pre.append({"check": "Immich impact", "ok": False, "blocking": False,
                        "detail": "Immich will be unavailable while this container is down."
                                  + (" Stopping the database while Immich runs can interrupt uploads." if "postgres" in name else "")})
        if immich and self.gov.immich_busy and verb != "start":
            pre.append({"check": "Immich is idle", "ok": False, "blocking": False,
                        "detail": "Immich is processing (uploads, thumbnails or ML). Consider waiting."})
        rb = {"start": "stop", "stop": "start", "restart": None}[verb]
        return {
            "type": "container", "verb": verb, "target": name,
            "summary": f"{verb.capitalize()} container {name}",
            "impact": "Docker restart policy still applies after a stop only until the next reboot/daemon restart."
            if verb == "stop" else f"The container will {verb}.",
            "risk": "high" if immich else "medium", "preconditions": pre,
            "confirm": {"level": "type", "text": name} if immich and verb != "start" else {"level": "click"},
            "before": before, "rollback": f"{rb} container {name}" if rb else "None needed.",
        }

    def _preview_backup(self) -> dict:
        b = (self.db.snapshot("backup") or {}).get("data", {})
        unit = self.cfg["backup"]["unit"]
        pre = [{"check": "Backup job configured", "ok": bool(unit), "detail": "Set [backup] unit in config.toml"},
               {"check": "No backup already running", "ok": not b.get("running"), "detail": ""}]
        if self.cfg["backup"]["drive_uuid"]:
            pre.insert(1, {"check": "Backup drive connected", "ok": bool((b.get("drive") or {}).get("connected")), "detail": ""})
        return {
            "type": "backup_run", "target": unit,
            "summary": "Run the backup job now", "risk": "low",
            "impact": f"Starts {unit or '(not configured)'}.service (systemd --user). It runs with whatever priority its unit defines.",
            "preconditions": pre,
            "confirm": {"level": "click"}, "before": {}, "rollback": "Not applicable.",
        }

    def _preview_files(self, kind: str, scan_id: int, paths: list[str]) -> dict:
        if not paths or len(paths) > 5000:
            raise ActionError("select between 1 and 5000 files")
        rows = [self.db.one("SELECT * FROM dup_files WHERE scan_id=? AND path=?", (scan_id, p)) for p in paths]
        if not all(rows):
            raise ActionError("some files are not part of this scan")
        total = sum(r["size"] for r in rows)
        from .util import human_bytes
        text = {
            "quarantine": (f"Move {len(paths)} duplicate file(s) ({human_bytes(total)}) to quarantine",
                           "Files move to .guardian-quarantine on the same disk; nothing is deleted. You can restore them.",
                           "Restore from the Duplicates page."),
            "restore": (f"Restore {len(paths)} file(s) from quarantine", "Files move back to their original location.",
                        "Quarantine them again."),
            "purge": (f"PERMANENTLY delete {len(paths)} quarantined file(s) ({human_bytes(total)})",
                      "This frees the space and cannot be undone.", "None: deletion is permanent."),
        }[kind]
        return {"type": kind, "target": f"scan {scan_id}", "scan_id": scan_id, "paths": paths,
                "summary": text[0], "impact": text[1], "risk": "high" if kind == "purge" else "low",
                "preconditions": [], "before": {"files": len(paths), "bytes": total},
                "confirm": {"level": "type", "text": "DELETE"} if kind == "purge" else {"level": "click"},
                "rollback": text[2]}

    # ------------------------------------------------------------------ execute
    def execute(self, token: str, confirm_text: str, user: str, client: str) -> dict:
        plan = _unsign(token)
        if plan["confirm"]["level"] == "type" and confirm_text.strip() != plan["confirm"]["text"]:
            raise ActionError(f"type '{plan['confirm']['text']}' to confirm")
        now = time.time()
        self._used = {n: t for n, t in self._used.items() if now - t < TOKEN_TTL}
        if plan["nonce"] in self._used:
            raise ActionError("this confirmation was already used; preview again")
        self._used[plan["nonce"]] = plan["issued"]
        # Re-check preconditions against the live system, not the preview.
        fresh = self.preview({"type": plan["type"], "verb": plan.get("verb"), "target": plan.get("target"),
                              "audit_id": plan.get("audit_id"), "scan_id": plan.get("scan_id"), "paths": plan.get("paths")})
        if fresh["blocked"]:
            raise ActionError("preconditions changed: " + "; ".join(p["check"] for p in fresh["blocked"]))
        kind = plan["type"]
        result, after, status = {}, {}, "done"
        try:
            if kind == "service":
                result = _exec_call(plan["verb"], plan["target"])
                after = _unit_state(plan["target"])
                status = "done" if result.get("ok") else "failed"
            elif kind == "service_rollback":
                result = {"steps": [_exec_call(v, plan["target"]) for v in plan["verbs"]]}
                after = _unit_state(plan["target"])
                status = "done" if all(s.get("ok") for s in result["steps"]) else "failed"
            elif kind == "container":
                docker_api(f"/containers/{plan['target']}/{plan['verb']}?t=30", method="POST", timeout=90)
                time.sleep(2)
                after = _container_state(plan["target"])
            elif kind == "backup_run":
                out = run(["systemctl", "--user", "start", "--no-block", plan["target"] + ".service"])
                result = {"started": True, "output": out}
            elif kind == "quarantine":
                result = {"files": duplicates.quarantine(self.db, self.cfg, plan["scan_id"], plan["paths"])}
            elif kind == "restore":
                result = {"files": duplicates.restore(self.db, plan["scan_id"], plan["paths"])}
            elif kind == "purge":
                result = {"files": duplicates.purge(self.db, plan["scan_id"], plan["paths"])}
            if "files" in result:
                ok = sum(1 for f in result["files"] if f["ok"])
                status = "done" if ok == len(result["files"]) else ("partial" if ok else "failed")
        except Exception as e:
            status, result = "failed", {"error": str(e)}
        aid = self.db.audit(user=user, client=client, action=f"{kind}.{plan.get('verb', '')}".rstrip("."),
                            target=plan["target"], status=status, summary=plan["summary"],
                            before_state=plan["before"], after_state=after, result=result, rollback=plan["rollback"])
        return {"audit_id": aid, "status": status, "result": result, "after": after}
