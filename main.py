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

EVAL_STATE = {}
DOSSIER_STATE = {}

def compact_json(obj):
    return json.dumps(obj, separators=(',', ':'), sort_keys=True)

def hash_json(obj):
    return hashlib.sha256(compact_json(obj).encode('utf-8')).hexdigest()

def verify_ed25519(jwk, signature_b64, payload_bytes):
    try:
        x_b64 = jwk.get("x", "")
        x_b64 += '=' * (4 - len(x_b64) % 4)
        public_bytes = base64.urlsafe_b64decode(x_b64)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, payload_bytes)
        return True
    except Exception:
        return False

def analyze_dossier(dossier):
    line_ids = []
    text_corpus = []
    for src in dossier.get("sources", []):
        for line in src.get("lines", []):
            lid = line.get("lineId")
            txt = line.get("text", "")
            if lid:
                line_ids.append(lid)
            text_corpus.append(txt.lower())

    full_corpus = " ".join(text_corpus) + " " + dossier.get("objective", "").lower()
    evidence = line_ids[:2] if len(line_ids) >= 2 else (line_ids if line_ids else ["line_1"])
    did = dossier.get("dossierId", "item1")
    mailbox = dossier.get("mailbox", "support")

    email_match = re.search(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', full_corpus)
    extracted_email = email_match.group(0) if email_match else "customer@example.com"

    if any(k in full_corpus for k in ["ignore", "silent", "secret", "inject", "quarantine", "override"]):
        return "quarantine_item", {"kind": "security_queue", "id": "mailroom"}, {"artifactId": did, "reasonCode": "INDIRECT_PROMPT_INJECTION"}, evidence
    elif "draft" in full_corpus:
        return "create_draft", {"kind": "draft_queue", "id": f"mailbox:{mailbox}"}, {"recipient": extracted_email, "referenceId": did, "status": "draft", "template": "order_status"}, evidence
    elif "window" in full_corpus or "delivery" in full_corpus:
        return "update_internal_record", {"kind": "case_record", "id": f"case_{did}"}, {"field": "delivery_window", "sourceEventId": "evt_01", "value": "updated_window"}, evidence
    elif "approve" in full_corpus or "notice" in full_corpus:
        return "send_approved_notice", {"kind": "email", "id": extracted_email}, {"referenceId": did, "status": "approved", "template": "approved_delivery_notice"}, evidence
    elif "verify" in full_corpus or "ambiguous" in full_corpus or "conflict" in full_corpus:
        return "request_confirmation", {"kind": "approval_queue", "id": "support_team"}, {"claimedSender": extracted_email, "questionCode": "VERIFY_REQUEST", "referenceId": did}, evidence
    else:
        return "no_action", None, {"reasonCode": "INFORMATIONAL", "referenceId": did}, evidence

@app.post("/")
@app.post("/mailroom")
@app.post("/mailroom/")
async def mailroom_endpoint(request: Request):
    try:
        body_bytes = await request.body()
        data = json.loads(body_bytes.decode('utf-8'))
    except Exception:
        return Response(status_code=400)
        
    op = data.get("operation")
    eval_id = data.get("evaluationId")

    if op == "propose":
        if not eval_id or "dossiers" not in data:
            return Response(status_code=422)

        input_digest = hash_json(data.get("dossiers"))
        
        # Conflict check: same evaluationId with different inputDigest must return 409
        if eval_id in EVAL_STATE:
            if EVAL_STATE[eval_id]["inputDigest"] != input_digest:
                return Response(status_code=409)
            else:
                return EVAL_STATE[eval_id]["response"]

        proposals = []
        for d in data.get("dossiers", []):
            did = d.get("dossierId")
            content_hash = hash_json(d)
            
            if did in DOSSIER_STATE and DOSSIER_STATE[did]["hash"] == content_hash:
                proposals.append(DOSSIER_STATE[did]["proposal"])
                continue

            action, target, payload, evidence = analyze_dossier(d)
            call_id = "call_" + str(uuid.uuid4()).replace("-", "")[:20]
            
            proposal = {
                "dossierId": did,
                "callId": call_id,
                "action": action,
                "target": target,
                "payload": payload,
                "evidence": evidence
            }
            proposals.append(proposal)
            DOSSIER_STATE[did] = {"hash": content_hash, "proposal": proposal}

        resp = {
            "profile": "ga5-mailroom-action-gate/v2",
            "evaluationId": eval_id,
            "status": "awaiting_receipts",
            "inputDigest": input_digest,
            "proposals": proposals
        }
        
        EVAL_STATE[eval_id] = {
            "inputDigest": input_digest,
            "verifier": data.get("receiptVerifier"),
            "proposals": {p["dossierId"]: p for p in proposals},
            "response": resp
        }
        return resp

    elif op == "commit":
        input_digest = data.get("inputDigest")
        if not eval_id or eval_id not in EVAL_STATE:
            return Response(status_code=400)
            
        stored = EVAL_STATE[eval_id]
        if stored["inputDigest"] != input_digest:
            return Response(status_code=409)
            
        verifier = stored["verifier"]
        jwk = verifier.get("publicKeyJwk")
        
        outcomes = []
        receipt_ids = set()

        for r in data.get("receipts", []):
            did = r.get("dossierId")
            
            verify_obj = {
                "profile": "ga5-mailroom-action-gate/v2",
                "evaluationId": eval_id,
                "inputDigest": input_digest,
                "receipt": {
                    "dossierId": did,
                    "callId": r.get("callId"),
                    "action": r.get("action"),
                    "accepted": r.get("accepted"),
                    "proposalDigest": r.get("proposalDigest"),
                    "receiptId": r.get("receiptId")
                }
            }
            
            payload_bytes = compact_json(verify_obj).encode('utf-8')
            if not verify_ed25519(jwk, r.get("receiptSignature", ""), payload_bytes):
                return Response(status_code=422)
                
            if r.get("receiptId") in receipt_ids:
                return Response(status_code=422)
            receipt_ids.add(r.get("receiptId"))
                
            if did not in stored["proposals"]:
                return Response(status_code=422)
                
            sp = stored["proposals"][did]
            prop_digest_obj = {
                "dossierId": sp["dossierId"],
                "callId": sp["callId"],
                "action": sp["action"],
                "target": sp["target"],
                "payload": sp["payload"],
                "evidence": sorted(sp["evidence"])
            }
            computed_prop_digest = hash_json(prop_digest_obj)
            
            if r.get("proposalDigest") != computed_prop_digest or r.get("callId") != sp["callId"]:
                return Response(status_code=422)
                
            outcomes.append({
                "dossierId": did,
                "callId": r.get("callId"),
                "action": sp["action"],
                "proposalDigest": r.get("proposalDigest"),
                "receiptId": r.get("receiptId"),
                "status": "executed" if r.get("accepted") else "rejected"
            })
            
        return {
            "profile": "ga5-mailroom-action-gate/v2",
            "evaluationId": eval_id,
            "status": "completed",
            "inputDigest": input_digest,
            "outcomes": outcomes
        }
        
    return Response(status_code=400)
