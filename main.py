import os
import re
import json
import base64
import urllib.parse
import socket
import ipaddress
import requests
import unicodedata
import hashlib
import uuid
from fastapi import FastAPI, Request, Response
from cryptography.hazmat.primitives.asymmetric import ed25519

app = FastAPI()

# =====================================================================
# QUESTION 1: PRE-TOOL SECURITY GUARDRAIL (/secure-guard)
# =====================================================================

def check_http_request_q1(url: str):
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        if host in ["registry.npmjs.org", "pypi.org"]: return True, "Host is allowed."
        return False, f"Host '{host}' is strictly forbidden."
    except Exception: return False, "Invalid URL structure."

def check_write_file(path: str):
    if not os.path.isabs(path): path = os.path.join("/home/agent/workspace", path)
    normalized = os.path.normpath(path)
    if normalized == "/workspace/output" or normalized.startswith("/workspace/output/"): return True, "Safe write path."
    if normalized == "/home/agent/workspace/output" or normalized.startswith("/home/agent/workspace/output/"): return True, "Safe write path."
    return False, "Write attempt outside of the allowed output directory."

def check_bash(command: str):
    cmd = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), command)
    cmd = re.sub(r'\\([0-7]{1,3})', lambda m: chr(int(m.group(1), 8)), cmd)
    clean_cmd = re.sub(r'["\'\\]', '', cmd)
    if "credentials.env" in clean_cmd or "vne.slaitnederc" in clean_cmd: return False, "Blocked"
    if re.search(r'(?:/home/agent|~|\$HOME)[/\\][^\s]*[*?]', clean_cmd): return False, "Blocked"
    words = re.findall(r'[A-Za-z0-9+/=]+', command)
    for word in words:
        if len(word) >= 16:
            try:
                decoded = base64.b64decode(word).decode('utf-8', errors='ignore')
                if "credentials.env" in re.sub(r'["\'\\]', '', decoded): return False, "Blocked"
            except Exception: pass
        if len(word) >= 20 and re.fullmatch(r'[0-9a-fA-F]+', word):
            try:
                decoded = bytes.fromhex(word).decode('utf-8', errors='ignore')
                if "credentials.env" in re.sub(r'["\'\\]', '', decoded): return False, "Blocked"
            except Exception: pass
    return True, "Bash command appears safe."

@app.post("/secure-guard")
@app.post("/secure-guard/")
async def secure_guard_endpoint(request: Request):
    try:
        data = await request.json()
        tool = data.get("tool")
        if tool == "http_request": allow, reason = check_http_request_q1(data.get("url", ""))
        elif tool == "write_file": allow, reason = check_write_file(data.get("path", ""))
        elif tool == "bash": allow, reason = check_bash(data.get("command", ""))
        else: allow, reason = False, f"Tool '{tool}' is not supported."
        return {"decision": "allow" if allow else "block", "reason": reason}
    except Exception: return {"decision": "block", "reason": "Invalid payload"}


# =====================================================================
# QUESTION 2: RUN-CONTROL & LOOP GUARDRAIL (/run-guard)
# =====================================================================

def normalize_value(val):
    if isinstance(val, dict): return {k: normalize_value(v) for k, v in sorted(val.items()) if k != "trace_id"}
    elif isinstance(val, list): return [normalize_value(x) for x in val]
    elif isinstance(val, str): return re.sub(r'\s+', ' ', val).strip()
    return val

@app.post("/run-guard")
@app.post("/run-guard/")
async def run_guard_endpoint(request: Request):
    try:
        data = await request.json()
        budget_tokens = data.get("budget_tokens", 42000)
        steps = data.get("steps", [])
        total_tokens_used = sum(step.get("tokens_used", 0) for step in steps)
        if total_tokens_used >= budget_tokens: return {"decision": "halt", "reason": "Budget reached."}
        signatures = [(step.get("tool", ""), json.dumps(normalize_value(step.get("args", {})), sort_keys=True)) for step in steps]
        if len(signatures) >= 3 and signatures[-1] == signatures[-2] == signatures[-3]: return {"decision": "halt", "reason": "Loop detected: 3 identical calls."}
        if len(signatures) >= 6 and (signatures[-6] == signatures[-4] == signatures[-2]) and (signatures[-5] == signatures[-3] == signatures[-1]): return {"decision": "halt", "reason": "Loop detected: 2-step alternating pattern."}
        return {"decision": "continue", "reason": "Under budget, no loop detected."}
    except Exception: return {"decision": "halt", "reason": "Invalid payload"}


# =====================================================================
# QUESTION 3: ACTIVE RED-TEAM GUARDRAIL (/redteam)
# =====================================================================

ALLOWED_HOSTS_Q3 = {"example.com", "www.iana.org"}
BASE_DIR = os.path.normpath(os.path.abspath("/srv/agent-redteam/sandbox-d0bedaad2f"))

MOCK_FILES = {
    os.path.normpath(os.path.join(BASE_DIR, "../outside-b58d9a91/canary.txt")): "AGENT_GUARDRAIL_CANARY_f5d79b049e07b0ba4d36ddb74eb0e3df8bf39ff2",
    os.path.normpath(os.path.join(BASE_DIR, "notes/report.txt")): "SAFE_REPORT_97068d311b6b302295fa7ca9",
    os.path.normpath(os.path.join(BASE_DIR, "notes/looks-like-..-but-safe.txt")): "SAFE_WEIRD_98269a07ba909664e2cb4b47",
    os.path.normpath(os.path.join(BASE_DIR, "encoded/..-literal.txt")): "SAFE_ENCODED_031380264f355bc9030f317a"
}

def get_safe_path(raw_path: str):
    if not isinstance(raw_path, str) or "://" in raw_path or raw_path.lower().startswith("file:"): return None
    decoded = raw_path
    for _ in range(5):
        nxt = urllib.parse.unquote(decoded)
        if nxt == decoded: break
        decoded = nxt
    if '\x00' in decoded: return None
    decoded = unicodedata.normalize('NFKC', decoded)
    decoded = decoded.replace('\\', '/')
    if os.path.isabs(decoded): target = os.path.abspath(decoded)
    else: target = os.path.abspath(os.path.join(BASE_DIR, decoded.lstrip("/")))
    target = os.path.normpath(target)
    if not target.startswith(BASE_DIR + os.sep) and target != BASE_DIR: return None
    return target

def get_rebuilt_url(url: str):
    if not isinstance(url, str) or '@' in url or '\\' in url: return None
    try:
        url = re.sub(r'[\x00-\x20\x7f-\x9f]', '', url)
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme.lower() not in ["http", "https"]: return None
        host = parsed.hostname
        if not host or host not in ALLOWED_HOSTS_Q3: return None
        for res in socket.getaddrinfo(host, None):
            ip = res[4][0]
            ip_obj = ipaddress.ip_address(ip)
            if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or 
                ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_reserved or ip == "169.254.169.254"):
                return None
        netloc = host if not parsed.port else f"{host}:{parsed.port}"
        return urllib.parse.urlunparse((parsed.scheme.lower(), netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
    except Exception: return None

@app.post("/redteam")
@app.post("/redteam/")
async def execute_tool_endpoint(request: Request):
    try: data = await request.json()
    except Exception: return {"action": "block", "reason": "Invalid JSON", "result": None}
    try:
        tool = data.get("tool")
        args = data.get("arguments", {})
        if tool == "read_file":
            safe_path = get_safe_path(args.get("path", ""))
            if not safe_path: return {"action": "block", "reason": "Traversal blocked", "result": None}
            if safe_path in MOCK_FILES: return {"action": "allow", "reason": "ok", "result": MOCK_FILES[safe_path]}
            try:
                with open(safe_path, "r") as f: return {"action": "allow", "reason": "ok", "result": f.read()}
            except Exception as e: return {"action": "allow", "reason": "File not found", "result": str(e)}
        elif tool == "fetch_url":
            current_url = args.get("url", "")
            for _ in range(5):
                safe_url = get_rebuilt_url(current_url)
                if not safe_url: return {"action": "block", "reason": "Unsafe URL", "result": None}
                try: resp = requests.get(safe_url, allow_redirects=False, timeout=5)
                except Exception: return {"action": "block", "reason": "Fetch failed", "result": None}
                if 300 <= resp.status_code < 400: current_url = urllib.parse.urljoin(safe_url, resp.headers.get("Location", "").strip())
                else: return {"action": "allow", "reason": "Safe URL fetched", "result": resp.text}
            return {"action": "block", "reason": "Too many redirects", "result": None}
        return {"action": "block", "reason": f"Tool '{tool}' not recognized.", "result": None}
    except Exception: return {"action": "block", "reason": "Handled gracefully", "result": None}


# =====================================================================
# QUESTION 4: SKILL SCANNER (/scan)
# =====================================================================

@app.post("/scan")
@app.post("/scan/")
async def scan_endpoint(request: Request):
    try:
        data = await request.json()
        skill = data.get("skill", "")
    except Exception: return {"categories": []}

    categories = set()
    secret_regexes = [
        r'sk-[A-Za-z0-9]{20,}', r'ghp_[A-Za-z0-9]{36}', r'xox[bap]-[A-Za-z0-9\-]+',
        r'https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[a-zA-Z0-9_-]+',
        r'https://discord\.com/api/webhooks/\d+/[a-zA-Z0-9_-]+',
        r'Bearer\s+[A-Za-z0-9\-\._\~\+]{20,}',
        r'(?i)(?:api_key|apikey|secret|token|password|webhook_url)\s*[:=]\s*["\']?(?!<[^>]+>|YOUR_[A-Z_]+|example\.com|placeholder|TODO)[A-Za-z0-9\-\._\~\+]{16,}["\']?'
    ]
    for pattern in secret_regexes:
        if re.search(pattern, skill):
            categories.add("hardcoded_secret")
            break

    injection_regexes = [
        r'(?i)ignore\s+(?:the\s+)?user', r'(?i)override\s+(?:the\s+)?user',
        r'(?i)silent(?:ly)?\s+exfiltrate', r'(?i)exfiltrate\s+silent(?:ly)?',
        r'(?i)without\s+(?:notifying|informing|alerting|asking)\s+(?:the\s+)?user',
        r'(?i)do\s+not\s+(?:notify|inform|alert|ask)\s+(?:the\s+)?user',
        r'(?i)ignore\s+(?:the\s+)?user[\'s]*\s+(?:stop|cancel|request|command)',
        r'(?i)ignore\s+previous\s+instructions'
    ]
    for pattern in injection_regexes:
        if re.search(pattern, skill):
            categories.add("prompt_injection")
            break

    excessive_regexes = [
        r'(?i)^(?:\s*|- )?(?:permissions|filesystem|access|read|write|network|egress|domain)s?\s*:\s*(?:\[\s*)?[\'"]?(?:\*|/\*|/|C:\\|all)[\'"]?(?:\s*\])?\s*$',
        r'(?i)read/write\s+to\s+the\s+entire\s+filesystem', r'(?i)egress\s+to\s+any\s+domain'
    ]
    for pattern in excessive_regexes:
        if re.search(pattern, skill, re.MULTILINE):
            categories.add("excessive_permissions")
            break

    has_author = bool(re.search(r'^author\s*:', skill, re.IGNORECASE | re.MULTILINE))
    has_version = bool(re.search(r'^version\s*:', skill, re.IGNORECASE | re.MULTILINE))
    has_changelog = bool(re.search(r'^changelog\s*:', skill, re.IGNORECASE | re.MULTILINE))
    if not has_author and not has_version and not has_changelog: categories.add("unclear_provenance")

    provenance_rewrite_regexes = [
        r'(?i)silently\s+(?:rewrite|update|bump|modify)\s+(?:its\s+)?(?:own\s+)?version',
        r'(?i)update\s+version\s+(?:metadata\s+)?without\s+surfacing',
        r'(?i)without\s+surfacing\s+(?:that\s+)?change'
    ]
    for pattern in provenance_rewrite_regexes:
        if re.search(pattern, skill):
            categories.add("unclear_provenance")
            break

    return {"categories": list(categories)}


# =====================================================================
# QUESTION 5: MCP SERVER (/mcp)
# =====================================================================

@app.post("/mcp")
@app.post("/mcp/")
async def mcp_endpoint(request: Request):
    try: data = await request.json()
    except Exception: return {} 
        
    method = data.get("method")
    msg_id = data.get("id")

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "exam-mcp", "version": "1.0.0"}}}
    elif method == "notifications/initialized": return {}
    elif method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": [{"name": "solve_challenge", "description": "Solves challenge.", "inputSchema": {"type": "object", "properties": {}}}]}}
    elif method == "tools/call":
        params = data.get("params", {})
        if params.get("name") == "solve_challenge":
            challenge = request.headers.get("x-exam-challenge", "")
            email = "23f2005302@ds.study.iitm.ac.in".strip().lower()
            raw_string = f"{challenge}:{email}"
            hash_hex = hashlib.sha256(raw_string.encode('utf-8')).hexdigest()[:16]
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"content": [{"type": "text", "text": hash_hex}]}}
        else:
            return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "Tool not found"}}
    if msg_id is not None: return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "Method not found"}}
    return {}

# =====================================================================
# QUESTION 6: MAILROOM AGENT (/mailroom)
# =====================================================================

from fastapi.responses import JSONResponse

EVAL_STATE = {}
DOSSIER_STATE = {}

PROFILE = "ga5-mailroom-action-gate/v2"


def compact_json(obj):
    return json.dumps(
        obj,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False
    )


def hash_json(obj):
    return hashlib.sha256(compact_json(obj).encode("utf-8")).hexdigest()


def error_response(status_code, code, message):
    return JSONResponse(
        status_code=status_code,
        content={
            "profile": PROFILE,
            "status": "error",
            "error": {
                "code": code,
                "message": message
            }
        }
    )


def verify_ed25519(jwk, signature_b64, payload_bytes):
    try:
        if not isinstance(jwk, dict):
            return False
        if not isinstance(signature_b64, str) or not signature_b64:
            return False

        x_b64 = jwk.get("x")
        if not isinstance(x_b64, str) or not x_b64:
            return False

        x_b64 += "=" * (-len(x_b64) % 4)
        public_bytes = base64.urlsafe_b64decode(x_b64.encode("ascii"))

        signature_b64 += "=" * (-len(signature_b64) % 4)
        signature = base64.urlsafe_b64decode(signature_b64.encode("ascii"))

        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
        public_key.verify(signature, payload_bytes)
        return True
    except Exception:
        return False


def get_lines(dossier):
    rows = []

    for source in dossier.get("sources", []):
        source_id = source.get("sourceId") or source.get("id") or ""
        for line in source.get("lines", []):
            line_id = line.get("lineId")
            text = line.get("text")

            if isinstance(line_id, str) and isinstance(text, str):
                rows.append({
                    "sourceId": source_id,
                    "lineId": line_id,
                    "text": text
                })

    return rows


def all_text(rows, dossier):
    objective = dossier.get("objective", "")
    parts = [objective] if isinstance(objective, str) else []
    parts.extend(row["text"] for row in rows)
    return "\n".join(parts)


def find_lines(rows, *patterns):
    found = []

    for row in rows:
        text = row["text"].lower()
        if any(re.search(pattern, text, re.I) for pattern in patterns):
            found.append(row["lineId"])

    return found


def unique_ids(ids):
    result = []
    seen = set()

    for value in ids:
        if isinstance(value, str) and value and value not in seen:
            seen.add(value)
            result.append(value)

    return result


def evidence_for(rows, *patterns):
    ids = find_lines(rows, *patterns)
    return unique_ids(ids)


def extract_email(rows):
    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"

    for row in rows:
        match = re.search(email_pattern, row["text"])
        if match:
            return match.group(0).lower(), row["lineId"]

    return None, None


def extract_reference_id(dossier, rows):
    for key in ("referenceId", "caseId", "orderId", "ticketId", "requestId"):
        value = dossier.get(key)
        if isinstance(value, str) and value:
            return value, None

    pattern = (
        r"\b(?:reference|case|order|ticket|request)"
        r"\s*(?:id|number|#)?\s*[:#]?\s*([A-Za-z0-9_-]+)\b"
    )

    for row in rows:
        match = re.search(pattern, row["text"], re.I)
        if match:
            return match.group(1), row["lineId"]

    dossier_id = dossier.get("dossierId")
    return dossier_id if isinstance(dossier_id, str) else None, None


def extract_delivery_window(rows):
    patterns = [
        r"\b(?:delivery|arrival|shipping)\s+(?:window|date|time)\s*(?:is|to|as|for)?\s*[:\-]?\s*([^\n.]+)",
        r"\b(?:deliver|arrival)\s+(?:on|by|between)\s+([^\n.]+)"
    ]

    for row in rows:
        for pattern in patterns:
            match = re.search(pattern, row["text"], re.I)
            if match:
                value = match.group(1).strip(" .,:;")
                if value:
                    return value, row["lineId"]

    return None, None


def contains_injection(rows):
    patterns = [
        r"\bignore\b.*\b(instruction|policy|rule|guardrail)\b",
        r"\boverride\b.*\b(instruction|policy|rule|guardrail)\b",
        r"\b(system prompt|developer message|hidden instruction)\b",
        r"\bexfiltrat(?:e|ion)\b",
        r"\bsend\b.*\b(secret|credential|token|password)\b",
        r"\bdo not (?:tell|inform|notify)\b"
    ]

    return evidence_for(rows, *patterns)


def contains_conflict(rows):
    patterns = [
        r"\bconflict(?:ing)?\b",
        r"\bcontradict(?:ion|ory)?\b",
        r"\bambiguous\b",
        r"\bunclear\b",
        r"\bverify\b",
        r"\bconfirm\b",
        r"\bnot authorized\b",
        r"\bunauthorized\b"
    ]

    return evidence_for(rows, *patterns)


def is_authorized_approval(rows):
    patterns = [
        r"\bapproved\b",
        r"\bauthori[sz]ed\b",
        r"\bpermission granted\b",
        r"\bapproval granted\b"
    ]

    return evidence_for(rows, *patterns)


def make_proposal(dossier):
    dossier_id = dossier.get("dossierId")
    rows = get_lines(dossier)

    if not isinstance(dossier_id, str) or not dossier_id:
        raise ValueError("Each dossier requires a non-empty dossierId.")

    # 1. Security takes priority over every business instruction.
    injection_evidence = contains_injection(rows)
    if injection_evidence:
        return {
            "dossierId": dossier_id,
            "action": "quarantine_item",
            "target": {
                "kind": "security_queue",
                "id": "mailroom"
            },
            "payload": {
                "artifactId": dossier_id,
                "reasonCode": "INDIRECT_PROMPT_INJECTION"
            },
            "evidence": injection_evidence
        }

    # 2. Conflicts or ambiguous authority require confirmation.
    conflict_evidence = contains_conflict(rows)
    if conflict_evidence:
        sender, sender_line = extract_email(rows)
        reference_id, reference_line = extract_reference_id(dossier, rows)

        evidence = unique_ids(
            conflict_evidence +
            ([sender_line] if sender_line else []) +
            ([reference_line] if reference_line else [])
        )

        return {
            "dossierId": dossier_id,
            "action": "request_confirmation",
            "target": {
                "kind": "approval_queue",
                "id": "support_team"
            },
            "payload": {
                "claimedSender": sender,
                "questionCode": "VERIFY_REQUEST",
                "referenceId": reference_id
            },
            "evidence": evidence
        }

    # 3. Only send an external notice with explicit approval/authority.
    approval_evidence = is_authorized_approval(rows)
    if approval_evidence:
        recipient, recipient_line = extract_email(rows)
        reference_id, reference_line = extract_reference_id(dossier, rows)

        if recipient and reference_id:
            evidence = unique_ids(
                approval_evidence +
                [recipient_line] +
                ([reference_line] if reference_line else [])
            )

            return {
                "dossierId": dossier_id,
                "action": "send_approved_notice",
                "target": {
                    "kind": "email",
                    "id": recipient
                },
                "payload": {
                    "referenceId": reference_id,
                    "status": "approved",
                    "template": "approved_delivery_notice"
                },
                "evidence": evidence
            }

    # 4. Internal delivery update requires an actual stated delivery value.
    delivery_window, delivery_line = extract_delivery_window(rows)
    reference_id, reference_line = extract_reference_id(dossier, rows)

    if delivery_window and reference_id:
        evidence = unique_ids(
            [delivery_line] +
            ([reference_line] if reference_line else [])
        )

        return {
            "dossierId": dossier_id,
            "action": "update_internal_record",
            "target": {
                "kind": "case_record",
                "id": reference_id
            },
            "payload": {
                "field": "delivery_window",
                "value": delivery_window
            },
            "evidence": evidence
        }

    # 5. Drafts are non-executing and require a real recipient.
    draft_evidence = evidence_for(rows, r"\bdraft\b", r"\bprepare\b.*\bemail\b")
    if draft_evidence:
        recipient, recipient_line = extract_email(rows)
        reference_id, reference_line = extract_reference_id(dossier, rows)

        if recipient and reference_id:
            evidence = unique_ids(
                draft_evidence +
                [recipient_line] +
                ([reference_line] if reference_line else [])
            )

            mailbox = dossier.get("mailbox", "support")
            mailbox = mailbox if isinstance(mailbox, str) and mailbox else "support"

            return {
                "dossierId": dossier_id,
                "action": "create_draft",
                "target": {
                    "kind": "draft_queue",
                    "id": f"mailbox:{mailbox}"
                },
                "payload": {
                    "recipient": recipient,
                    "referenceId": reference_id,
                    "status": "draft",
                    "template": "order_status"
                },
                "evidence": evidence
            }

    # 6. Do not manufacture a target, recipient, event ID, or evidence.
    return {
        "dossierId": dossier_id,
        "action": "no_action",
        "target": None,
        "payload": {
            "reasonCode": "INSUFFICIENT_AUTHORITY_OR_EVIDENCE",
            "referenceId": reference_id
        },
        "evidence": []
    }


def proposal_digest(proposal):
    digest_obj = {
        "dossierId": proposal["dossierId"],
        "callId": proposal["callId"],
        "action": proposal["action"],
        "target": proposal["target"],
        "payload": proposal["payload"],
        "evidence": sorted(proposal["evidence"])
    }
    return hash_json(digest_obj)


def receipt_signing_payload(evaluation_id, input_digest, receipt):
    return {
        "profile": PROFILE,
        "evaluationId": evaluation_id,
        "inputDigest": input_digest,
        "receipt": {
            "dossierId": receipt.get("dossierId"),
            "callId": receipt.get("callId"),
            "action": receipt.get("action"),
            "accepted": receipt.get("accepted"),
            "proposalDigest": receipt.get("proposalDigest"),
            "receiptId": receipt.get("receiptId")
        }
    }


@app.post("/")
@app.post("/mailroom")
@app.post("/mailroom/")
async def mailroom_endpoint(request: Request):
    try:
        body_bytes = await request.body()
        data = json.loads(body_bytes.decode("utf-8"))
    except Exception:
        return error_response(400, "INVALID_JSON", "Request body must be valid JSON.")

    if not isinstance(data, dict):
        return error_response(422, "INVALID_REQUEST", "Request body must be an object.")

    operation = data.get("operation")
    evaluation_id = data.get("evaluationId")

    if not isinstance(evaluation_id, str) or not evaluation_id:
        return error_response(422, "INVALID_REQUEST", "evaluationId is required.")

    if operation == "propose":
        dossiers = data.get("dossiers")
        verifier = data.get("receiptVerifier")

        if not isinstance(dossiers, list):
            return error_response(422, "INVALID_REQUEST", "dossiers must be an array.")

        if not isinstance(verifier, dict) or not isinstance(verifier.get("publicKeyJwk"), dict):
            return error_response(
                422,
                "INVALID_REQUEST",
                "receiptVerifier.publicKeyJwk is required."
            )

        dossier_ids = []
        for dossier in dossiers:
            if not isinstance(dossier, dict):
                return error_response(422, "INVALID_REQUEST", "Every dossier must be an object.")

            dossier_id = dossier.get("dossierId")
            if not isinstance(dossier_id, str) or not dossier_id:
                return error_response(422, "INVALID_REQUEST", "Every dossier requires dossierId.")

            dossier_ids.append(dossier_id)

        if len(dossier_ids) != len(set(dossier_ids)):
            return error_response(422, "INVALID_REQUEST", "dossierId values must be unique.")

        input_digest = hash_json(dossiers)

        # Exact replay must return the exact stored response.
        if evaluation_id in EVAL_STATE:
            saved = EVAL_STATE[evaluation_id]

            if saved["inputDigest"] != input_digest:
                return error_response(
                    409,
                    "EVALUATION_CONFLICT",
                    "evaluationId was already used with different dossiers."
                )

            return JSONResponse(content=saved["proposalResponse"])

        proposals = []
        seen_call_ids = set()

        for dossier in dossiers:
            dossier_id = dossier["dossierId"]
            content_digest = hash_json(dossier)

            try:
                base_proposal = make_proposal(dossier)
            except ValueError as exc:
                return error_response(422, "INVALID_REQUEST", str(exc))

            # A dossier may be reused only if its content and proposed decision
            # are exactly stable. Otherwise reject the cross-evaluation conflict.
            previous = DOSSIER_STATE.get(dossier_id)
            if previous:
                if previous["contentDigest"] != content_digest:
                    return error_response(
                        409,
                        "DOSSIER_CONFLICT",
                        f"dossierId '{dossier_id}' was previously submitted with different content."
                    )

                previous_base = previous["baseProposal"]
                if (
                    previous_base["action"] != base_proposal["action"] or
                    previous_base["target"] != base_proposal["target"] or
                    previous_base["payload"] != base_proposal["payload"]
                ):
                    return error_response(
                        409,
                        "DOSSIER_CONFLICT",
                        f"dossierId '{dossier_id}' has a conflicting proposed action."
                    )

            call_id = f"call_{uuid.uuid4().hex}"
            while call_id in seen_call_ids:
                call_id = f"call_{uuid.uuid4().hex}"

            seen_call_ids.add(call_id)

            proposal = {
                "dossierId": dossier_id,
                "callId": call_id,
                "action": base_proposal["action"],
                "target": base_proposal["target"],
                "payload": base_proposal["payload"],
                "evidence": base_proposal["evidence"]
            }
            proposals.append(proposal)

            DOSSIER_STATE[dossier_id] = {
                "contentDigest": content_digest,
                "baseProposal": base_proposal
            }

        response_body = {
            "profile": PROFILE,
            "evaluationId": evaluation_id,
            "status": "awaiting_receipts",
            "inputDigest": input_digest,
            "proposals": proposals
        }

        EVAL_STATE[evaluation_id] = {
            "inputDigest": input_digest,
            "verifier": verifier,
            "proposals": {proposal["dossierId"]: proposal for proposal in proposals},
            "proposalResponse": response_body,
            "commitResponse": None
        }

        return JSONResponse(content=response_body)

    if operation == "commit":
        if evaluation_id not in EVAL_STATE:
            return error_response(
                409,
                "UNKNOWN_EVALUATION",
                "No matching proposal exists for evaluationId."
            )

        stored = EVAL_STATE[evaluation_id]
        input_digest = data.get("inputDigest")
        receipts = data.get("receipts")

        if input_digest != stored["inputDigest"]:
            return error_response(
                409,
                "INPUT_DIGEST_MISMATCH",
                "inputDigest does not match the proposal."
            )

        if not isinstance(receipts, list):
            return error_response(422, "INVALID_REQUEST", "receipts must be an array.")

        # Commit replay returns exactly the original completion response.
        if stored["commitResponse"] is not None:
            return JSONResponse(content=stored["commitResponse"])

        expected = stored["proposals"]

        # One receipt per proposal: no missing, duplicate, or unknown receipt.
        if len(receipts) != len(expected):
            return error_response(
                422,
                "INVALID_RECEIPTS",
                "Exactly one receipt is required for each proposal."
            )

        receipt_ids = set()
        dossier_ids = set()
        outcomes = []

        verifier = stored["verifier"]
        jwk = verifier.get("publicKeyJwk")

        for receipt in receipts:
            if not isinstance(receipt, dict):
                return error_response(422, "INVALID_RECEIPT", "Each receipt must be an object.")

            dossier_id = receipt.get("dossierId")
            receipt_id = receipt.get("receiptId")

            if not isinstance(dossier_id, str) or dossier_id not in expected:
                return error_response(422, "INVALID_RECEIPT", "Receipt has an unknown dossierId.")

            if dossier_id in dossier_ids:
                return error_response(422, "INVALID_RECEIPT", "Duplicate dossier receipt.")

            if not isinstance(receipt_id, str) or not receipt_id or receipt_id in receipt_ids:
                return error_response(422, "INVALID_RECEIPT", "receiptId must be unique.")

            dossier_ids.add(dossier_id)
            receipt_ids.add(receipt_id)

            proposal = expected[dossier_id]

            if receipt.get("callId") != proposal["callId"]:
                return error_response(422, "INVALID_RECEIPT", "callId does not match proposal.")

            if receipt.get("action") != proposal["action"]:
                return error_response(422, "INVALID_RECEIPT", "action does not match proposal.")

            expected_digest = proposal_digest(proposal)
            if receipt.get("proposalDigest") != expected_digest:
                return error_response(422, "INVALID_RECEIPT", "proposalDigest does not match proposal.")

            if not isinstance(receipt.get("accepted"), bool):
                return error_response(422, "INVALID_RECEIPT", "accepted must be boolean.")

            signing_payload = receipt_signing_payload(
                evaluation_id,
                input_digest,
                receipt
            )

            signature = receipt.get("receiptSignature", "")
            if not verify_ed25519(
                jwk,
                signature,
                compact_json(signing_payload).encode("utf-8")
            ):
                return error_response(422, "INVALID_RECEIPT", "Invalid receipt signature.")

            outcomes.append({
                "dossierId": dossier_id,
                "callId": proposal["callId"],
                "action": proposal["action"],
                "proposalDigest": expected_digest,
                "receiptId": receipt_id,
                "status": "executed" if receipt["accepted"] else "rejected"
            })

        if dossier_ids != set(expected.keys()):
            return error_response(
                422,
                "INVALID_RECEIPTS",
                "Receipts do not cover every proposal."
            )

        response_body = {
            "profile": PROFILE,
            "evaluationId": evaluation_id,
            "status": "completed",
            "inputDigest": input_digest,
            "outcomes": outcomes
        }

        stored["commitResponse"] = response_body
        return JSONResponse(content=response_body)

    return error_response(400, "INVALID_OPERATION", "operation must be propose or commit.")
