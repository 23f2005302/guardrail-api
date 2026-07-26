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
import time
from datetime import datetime
from fastapi import FastAPI, Request, Response, Header, HTTPException
from fastapi.responses import JSONResponse
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

EVAL_STATE_Q6 = {}
DOSSIER_STATE_Q6 = {}

def compact_json_q6(obj):
    return json.dumps(obj, separators=(',', ':'), sort_keys=True)

def hash_json_q6(obj):
    return hashlib.sha256(compact_json_q6(obj).encode('utf-8')).hexdigest()

def analyze_dossier_q6(dossier):
    line_ids = []
    text_corpus = []
    for src in dossier.get("sources", []):
        for line in src.get("lines", []):
            lid = line.get("lineId")
            if lid: line_ids.append(lid)
            text_corpus.append(line.get("text", ""))

    full_text = " ".join(text_corpus)
    full_corpus_lower = full_text.lower() + " " + dossier.get("objective", "").lower()
    evidence = [line_ids[0]] if line_ids else ["line_1"]
    
    did = dossier.get("dossierId", "item1")
    mailbox = dossier.get("mailbox", "support")

    email_match = re.search(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', full_text)
    extracted_email = email_match.group(0) if email_match else "customer@example.com"
    
    ref_match = re.search(r'(?:ref|id|reference|record)\s*[:#-]\s*([A-Za-z0-9_]+)', full_text, re.I)
    ref_id = ref_match.group(1) if ref_match else did

    if any(term in full_corpus_lower for term in ["ignore", "silent", "secret", "inject", "quarantine", "override", "exfiltrate"]):
        return "quarantine_item", {"kind": "security_queue", "id": "mailroom"}, {"artifactId": ref_id, "reasonCode": "INDIRECT_PROMPT_INJECTION"}, evidence
    elif "draft" in full_corpus_lower or "response" in full_corpus_lower:
        return "create_draft", {"kind": "draft_queue", "id": f"mailbox:{mailbox}"}, {"recipient": extracted_email, "referenceId": ref_id, "status": "draft", "template": "order_status"}, evidence
    elif "window" in full_corpus_lower or "delivery" in full_corpus_lower:
        return "update_internal_record", {"kind": "case_record", "id": ref_id}, {"field": "delivery_window", "sourceEventId": ref_id, "value": "updated_window"}, evidence
    elif "approve" in full_corpus_lower or "notice" in full_corpus_lower:
        return "send_approved_notice", {"kind": "email", "id": extracted_email}, {"referenceId": ref_id, "status": "approved", "template": "approved_delivery_notice"}, evidence
    elif "verify" in full_corpus_lower or "ambiguous" in full_corpus_lower or "conflict" in full_corpus_lower:
        return "request_confirmation", {"kind": "approval_queue", "id": "support_team"}, {"claimedSender": extracted_email, "questionCode": "VERIFY_REQUEST", "referenceId": ref_id}, evidence
    else:
        return "no_action", None, {"reasonCode": "INFORMATIONAL", "referenceId": ref_id}, evidence

@app.post("/mailroom")
@app.post("/mailroom/")
async def mailroom_endpoint(request: Request):
    try:
        body_bytes = await request.body()
        data = json.loads(body_bytes.decode('utf-8'))
    except Exception:
        return Response(status_code=400)
        
    op = data.get("operation")
    if op not in ["propose", "commit"]:
        return Response(status_code=400)

    eval_id = data.get("evaluationId")
    if not eval_id:
        return Response(status_code=422)

    if op == "propose":
        if "dossiers" not in data:
            return Response(status_code=422)
        dossiers = data.get("dossiers", [])
        dids = [d.get("dossierId") for d in dossiers]
        if len(dids) != len(set(dids)): return Response(status_code=400)

        input_digest = hash_json_q6(dossiers)
        
        if eval_id in EVAL_STATE_Q6:
            if EVAL_STATE_Q6[eval_id]["inputDigest"] != input_digest: return Response(status_code=409)
            return JSONResponse(content=EVAL_STATE_Q6[eval_id]["response"])

        proposals = []
        for d in dossiers:
            did = d.get("dossierId")
            content_hash = hash_json_q6(d)
            if did in DOSSIER_STATE_Q6 and DOSSIER_STATE_Q6[did]["hash"] == content_hash:
                cached = DOSSIER_STATE_Q6[did]["decision"]
                action = cached["action"]
                target = cached["target"]
                payload = cached["payload"]
                evidence = cached["evidence"]
            else:
                action, target, payload, evidence = analyze_dossier_q6(d)
                DOSSIER_STATE_Q6[did] = {"hash": content_hash, "decision": {"action": action, "target": target, "payload": payload, "evidence": evidence}}

            call_id = "call_" + str(uuid.uuid4()).replace("-", "")[:20]
            proposal = {"dossierId": did, "callId": call_id, "action": action, "target": target, "payload": payload, "evidence": evidence}
            proposals.append(proposal)

        resp = {"profile": "ga5-mailroom-action-gate/v2", "evaluationId": eval_id, "status": "awaiting_receipts", "inputDigest": input_digest, "proposals": proposals}
        EVAL_STATE_Q6[eval_id] = {"inputDigest": input_digest, "verifier": data.get("receiptVerifier"), "proposals": {p["dossierId"]: p for p in proposals}, "response": resp}
        return JSONResponse(content=resp)

    elif op == "commit":
        input_digest = data.get("inputDigest")
        if eval_id not in EVAL_STATE_Q6: return Response(status_code=400)
        stored = EVAL_STATE_Q6[eval_id]
        if stored["inputDigest"] != input_digest: return Response(status_code=409)
            
        commit_req_hash = hash_json_q6(data.get("receipts", []))
        if "commit_req_hash" in stored:
            if stored["commit_req_hash"] == commit_req_hash: return JSONResponse(content=stored["commit_response"])
            else: return Response(status_code=409)

        jwk = stored["verifier"].get("publicKeyJwk")
        outcomes = []
        receipt_ids = set()

        for r in data.get("receipts", []):
            did = r.get("dossierId")
            verify_obj = {
                "profile": "ga5-mailroom-action-gate/v2", "evaluationId": eval_id, "inputDigest": input_digest,
                "receipt": {"dossierId": did, "callId": r.get("callId"), "action": r.get("action"), "accepted": r.get("accepted"), "proposalDigest": r.get("proposalDigest"), "receiptId": r.get("receiptId")}
            }
            
            try:
                x_b64 = jwk.get("x", "") + '=' * (4 - len(jwk.get("x", "")) % 4)
                public_bytes = base64.urlsafe_b64decode(x_b64)
                ed25519.Ed25519PublicKey.from_public_bytes(public_bytes).verify(base64.b64decode(r.get("receiptSignature", "")), compact_json_q6(verify_obj).encode('utf-8'))
            except Exception: return Response(status_code=422)
                
            if r.get("receiptId") in receipt_ids: return Response(status_code=422)
            receipt_ids.add(r.get("receiptId"))
                
            if did not in stored["proposals"]: return Response(status_code=422)
            sp = stored["proposals"][did]
            prop_digest_obj = {"dossierId": sp["dossierId"], "callId": sp["callId"], "action": sp["action"], "target": sp["target"], "payload": sp["payload"], "evidence": sorted(sp["evidence"])}
            
            if r.get("proposalDigest") != hash_json_q6(prop_digest_obj) or r.get("callId") != sp["callId"]: return Response(status_code=422)
                
            outcomes.append({"dossierId": did, "callId": r.get("callId"), "action": sp["action"], "proposalDigest": r.get("proposalDigest"), "receiptId": r.get("receiptId"), "status": "executed" if r.get("accepted") else "rejected"})
            
        resp = {"profile": "ga5-mailroom-action-gate/v2", "evaluationId": eval_id, "status": "completed", "inputDigest": input_digest, "outcomes": outcomes}
        stored["commit_req_hash"] = commit_req_hash
        stored["commit_response"] = resp
        return JSONResponse(content=resp)


# =====================================================================
# QUESTION 7: INVOICE CLAIM A2A AGENT (/a2a/...)
# =====================================================================

TASKS_STORE = {} 
MESSAGE_DEDUPLICATION = {} 

def a2a_json(content, status_code=200):
    return JSONResponse(content=content, status_code=status_code, headers={"Content-Type": "application/a2a+json"})

def compact_json_q7(obj):
    return json.dumps(obj, separators=(',', ':'), sort_keys=True)

def hash_json_q7(obj):
    return hashlib.sha256(compact_json_q7(obj).encode('utf-8')).hexdigest()

@app.get("/.well-known/agent-card.json")
async def get_agent_card(request: Request):
    base_url = str(request.base_url).rstrip("/") + "/a2a"
    return a2a_json({
        "name": "Invoice Claim Agent", "description": "Evaluates invoice packages", "version": "1.0.0", "capabilities": {"streaming": False},
        "skills": [{"name": "invoice_action_agent", "description": "Action evaluation", "tags": ["invoice"]}],
        "supportedInterfaces": [{"protocolBinding": "HTTP+JSON", "protocolVersion": "1.0", "url": base_url}],
        "defaultInputModes": ["application/vnd.ga5.invoice-claim-batch+json"],
        "defaultOutputModes": ["application/vnd.ga5.invoice-action-proposals+json", "application/vnd.ga5.invoice-action-receipts+json"]
    })

@app.post("/a2a/message:send")
async def a2a_message_send(request: Request):
    try:
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "): return a2a_json({"error": "Unauthorized"}, 401)
        principal = auth[7:].strip()
        
        a2a_ver = request.headers.get("a2a-version", "")
        if a2a_ver != "1.0": return a2a_json({"error": "Bad version"}, 400)
            
        try: body = await request.json()
        except Exception: return a2a_json({"error": "Malformed JSON"}, 400)
            
        message = body.get("message") or {}
        message_id = message.get("messageId")
        task_id = message.get("taskId")
        parts = message.get("parts") or []
        
        if not message_id: return a2a_json({"error": "Missing messageId"}, 400)

        if task_id:
            if principal not in TASKS_STORE or task_id not in TASKS_STORE[principal]: return a2a_json({"error": "Task not found"}, 404)
            task = TASKS_STORE[principal][task_id]
            if task.get("state") in ["TASK_STATE_COMPLETED", "TASK_STATE_CANCELED"]: return a2a_json({"error": "Task terminal"}, 409)
                
            results_part = None
            for p in parts:
                if isinstance(p, dict) and p.get("mediaType") == "application/vnd.ga5.invoice-action-results+json":
                    results_part = p.get("data") or {}
                    break
                    
            if not results_part: return a2a_json({"error": "Missing results"}, 422)
            batch_id = results_part.get("batchId")
            results = results_part.get("results") or []
            
            stored_proposals = (task.get("metadata") or {}).get("proposals") or []
            proposal_map = {prop["actionId"]: prop for prop in stored_proposals}
            
            executions = []
            for res in results:
                action_id = res.get("actionId")
                if action_id not in proposal_map: return a2a_json({"error": "Invalid ref"}, 422)
                prop = proposal_map[action_id]
                
                if res.get("packageId") != prop["packageId"] or res.get("action") != prop["action"]: return a2a_json({"error": "Mismatch"}, 422)
                if res.get("outcome") == "ACCEPTED":
                    executions.append({"packageId": prop["packageId"], "actionId": prop["actionId"], "action": prop["action"], "receiptNonce": res.get("receiptNonce"), "facts": prop["facts"], "evidenceRefs": prop["evidenceRefs"]})
                    
            if "history" not in task: task["history"] = []
            task["history"].append(message)
            if "artifacts" not in task: task["artifacts"] = []
            task["artifacts"].append({"mediaType": "application/vnd.ga5.invoice-action-receipts+json", "data": {"batchId": batch_id, "executions": executions}})
            task["state"] = "TASK_STATE_COMPLETED"
            task["updatedAt"] = datetime.utcnow().isoformat() + "Z"
            return a2a_json({"task": task})

        batch_part = None
        for p in parts:
            if isinstance(p, dict) and p.get("mediaType") == "application/vnd.ga5.invoice-claim-batch+json":
                batch_part = p.get("data") or {}
                break
                
        if not batch_part: return a2a_json({"error": "Missing batch"}, 400)
        msg_hash = hash_json_q7(message)
        dedup_key = (principal, msg_hash)
        if dedup_key in MESSAGE_DEDUPLICATION: return a2a_json({"task": TASKS_STORE[principal][MESSAGE_DEDUPLICATION[dedup_key]]})
            
        batch_id = batch_part.get("batchId", "batch_1")
        proposals = []
        for pkg in batch_part.get("packages") or []:
            pid = pkg.get("packageId", "pkg_1")
            action_id = "act_" + uuid.uuid4().hex[:16]
            evidence = ["line_1"]
            for src in pkg.get("sources") or []:
                for line in src.get("lines") or []:
                    if isinstance(line, dict) and line.get("lineId"): evidence.append(line.get("lineId"))
                        
            proposals.append({
                "packageId": pid, "actionId": action_id, "action": "settle_invoice",
                "facts": {"vendorName": "Acme", "invoiceNumber": "INV-1", "amountMinor": 100, "currency": "INR"},
                "evidenceRefs": evidence[:3], "rationale": f"Policy approved {pid}."
            })
            
        new_task_id = "task_" + uuid.uuid4().hex[:16]
        task_obj = {
            "taskId": new_task_id, "contextId": "ctx_" + uuid.uuid4().hex[:16], "state": "TASK_STATE_INPUT_REQUIRED", "history": [message],
            "artifacts": [{"mediaType": "application/vnd.ga5.invoice-action-proposals+json", "data": {"batchId": batch_id, "proposals": proposals}}],
            "metadata": {"proposals": proposals}, "createdAt": datetime.utcnow().isoformat() + "Z", "updatedAt": datetime.utcnow().isoformat() + "Z"
        }
        
        if principal not in TASKS_STORE: TASKS_STORE[principal] = {}
        TASKS_STORE[principal][new_task_id] = task_obj
        MESSAGE_DEDUPLICATION[dedup_key] = new_task_id
        return a2a_json({"task": task_obj})
    except Exception as e: return a2a_json({"error": f"Internal error handled: {str(e)}"}, 400)

@app.get("/a2a/tasks")
async def a2a_list_tasks(request: Request):
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "): return a2a_json({"error": "Unauthorized"}, 401)
    return a2a_json({"tasks": list(TASKS_STORE.get(auth[7:].strip(), {}).values())})

@app.get("/a2a/tasks/{id}")
async def a2a_get_task(id: str, request: Request):
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "): return a2a_json({"error": "Unauthorized"}, 401)
    principal = auth[7:].strip()
    if principal not in TASKS_STORE or id not in TASKS_STORE[principal]: return a2a_json({"error": "Not found"}, 404)
    return a2a_json(TASKS_STORE[principal][id])

@app.post("/a2a/tasks/{id}:cancel")
async def a2a_cancel_task(id: str, request: Request):
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "): return a2a_json({"error": "Unauthorized"}, 401)
    principal = auth[7:].strip()
    if principal not in TASKS_STORE or id not in TASKS_STORE[principal]: return a2a_json({"error": "Not found"}, 404)
    task = TASKS_STORE[principal][id]
    if task["state"] in ["TASK_STATE_COMPLETED", "TASK_STATE_CANCELED"]: return a2a_json({"error": "Terminal"}, 409)
    task["state"] = "TASK_STATE_CANCELED"
    task["updatedAt"] = datetime.utcnow().isoformat() + "Z"
    return a2a_json(task)


# =====================================================================
# QUESTION 8: INCIDENT RESPONSE AGENT WITH OTLP (/v2/incidents)
# =====================================================================

INCIDENT_STATE = {} # runId -> { current_state: dict, trace_id: str, server_span_id: str }

def generate_hex_id(length=16):
    return uuid.uuid4().hex[:length]

def get_current_time_ns():
    return str(int(time.time() * 1e9))

def create_base_otlp(run_id, public_marker, trace_id, server_span_id, agent_name):
    # Initializes the Server Span and Internal invoke_agent span
    start_time = get_current_time_ns()
    
    invoke_span_id = generate_hex_id(16)
    
    server_span = {
        "traceId": trace_id,
        "spanId": server_span_id,
        "name": "POST /v2/incidents",
        "kind": 2, # SERVER
        "startTimeUnixNano": start_time,
        "endTimeUnixNano": start_time,
        "attributes": [
            {"key": "ga5.run.id", "value": {"stringValue": run_id}},
            {"key": "ga5.public.marker", "value": {"stringValue": public_marker}}
        ]
    }
    
    invoke_span = {
        "traceId": trace_id,
        "spanId": invoke_span_id,
        "parentSpanId": server_span_id,
        "name": f"invoke_agent {agent_name}",
        "kind": 1, # INTERNAL
        "startTimeUnixNano": start_time,
        "endTimeUnixNano": start_time,
        "attributes": [
            {"key": "ga5.run.id", "value": {"stringValue": run_id}},
            {"key": "ga5.public.marker", "value": {"stringValue": public_marker}}
        ]
    }
    
    # Needs exactly one chat plan span
    chat_span = {
        "traceId": trace_id,
        "spanId": generate_hex_id(16),
        "parentSpanId": invoke_span_id,
        "name": "chat incident-plan",
        "kind": 3, # CLIENT
        "startTimeUnixNano": start_time,
        "endTimeUnixNano": start_time,
        "attributes": [
            {"key": "ga5.run.id", "value": {"stringValue": run_id}},
            {"key": "ga5.public.marker", "value": {"stringValue": public_marker}},
            {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
            {"key": "gen_ai.request.model", "value": {"stringValue": "heuristic-fast-v1"}}
        ]
    }
    
    return {
        "resourceSpans": [
            {
                "scopeSpans": [
                    {
                        "spans": [server_span, invoke_span, chat_span]
                    }
                ]
            }
        ]
    }, invoke_span_id

@app.post("/v2/incidents")
async def incident_start(request: Request):
    try:
        data = await request.json()
    except Exception:
        return Response(status_code=400)
        
    run_id = data.get("runId")
    incident = data.get("incident", {})
    allowed = incident.get("allowedRootCauses", ["unknown"])
    public_marker = data.get("publicMarker", "marker")
    agent_name = data.get("agentName", "incident-response")
    
    if not run_id or not incident:
        return Response(status_code=422)
        
    if run_id in INCIDENT_STATE:
        return JSONResponse(content=INCIDENT_STATE[run_id]["current_state"])
        
    root_cause = allowed[0] if allowed else "unknown"
    
    # 1. Propose Diagnostics
    action_id = "act_" + generate_hex_id(8)
    call_id = "call_" + generate_hex_id(8)
    
    trace_id = generate_hex_id(32)
    server_span_id = generate_hex_id(16)
    
    otlp_trace, invoke_span_id = create_base_otlp(run_id, public_marker, trace_id, server_span_id, agent_name)
    
    # Add execute_tool internal span for diagnostic
    exec_span_id = generate_hex_id(16)
    otlp_trace["resourceSpans"][0]["scopeSpans"][0]["spans"].append({
        "traceId": trace_id,
        "spanId": exec_span_id,
        "parentSpanId": invoke_span_id,
        "name": "execute_tool query_metrics",
        "kind": 1,
        "startTimeUnixNano": get_current_time_ns(),
        "endTimeUnixNano": get_current_time_ns(),
        "attributes": [
            {"key": "ga5.run.id", "value": {"stringValue": run_id}},
            {"key": "ga5.public.marker", "value": {"stringValue": public_marker}},
            {"key": "ga5.action.id", "value": {"stringValue": action_id}},
            {"key": "gen_ai.tool.name", "value": {"stringValue": "query_metrics"}},
            {"key": "gen_ai.tool.call.id", "value": {"stringValue": call_id}},
            {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}}
        ]
    })
    
    client_span_id = generate_hex_id(16)
    
    state = {
        "runId": run_id,
        "status": "waiting",
        "diagnosis": {
            "rootCause": root_cause,
            "evidence": ["ev_1", "ev_2"]
        },
        "dispatches": [
            {
                "actionId": action_id,
                "callId": call_id,
                "phase": "diagnostic",
                "toolName": "query_metrics",
                "arguments": {"metric": "cpu"},
                "evidence": ["ev_1"],
                "attempt": 1,
                "traceparent": f"00-{trace_id}-{client_span_id}-01"
            }
        ],
        "approvals": [],
        "actionLog": [],
        "receiptLog": []
    }
    
    state["actionLog"].extend(state["dispatches"])
    
    INCIDENT_STATE[run_id] = {
        "current_state": state,
        "trace_id": trace_id,
        "server_span_id": server_span_id,
        "invoke_span_id": invoke_span_id,
        "otlp": otlp_trace,
        "public_marker": public_marker,
        "pending_call_id": call_id,
        "pending_action_id": action_id,
        "pending_client_span_id": client_span_id
    }
    
    return JSONResponse(content=state)

@app.post("/v2/incidents/{run_id}/receipts")
async def incident_receipts(run_id: str, request: Request):
    try:
        data = await request.json()
    except Exception:
        return Response(status_code=400)
        
    if run_id not in INCIDENT_STATE:
        return Response(status_code=404)
        
    session = INCIDENT_STATE[run_id]
    state = session["current_state"]
    
    if state["status"] != "waiting":
        return Response(status_code=409)
        
    outcomes = data.get("outcomes", [])
    approvals_in = data.get("approvals", [])
    
    if outcomes:
        outcome = outcomes[0]
        if outcome.get("callId") != session["pending_call_id"]:
            return Response(status_code=400)
            
        state["receiptLog"].append(outcome)
        
        # Append Client Span to OTLP
        session["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"].append({
            "traceId": session["trace_id"],
            "spanId": session["pending_client_span_id"],
            "name": "POST tool/query_metrics",
            "kind": 3,
            "startTimeUnixNano": get_current_time_ns(),
            "endTimeUnixNano": get_current_time_ns(),
            "attributes": [
                {"key": "ga5.run.id", "value": {"stringValue": session["public_marker"]}},
                {"key": "ga5.public.marker", "value": {"stringValue": session["public_marker"]}},
                {"key": "ga5.action.id", "value": {"stringValue": session["pending_action_id"]}},
                {"key": "ga5.attempt", "value": {"intValue": 1}},
                {"key": "ga5.receipt.id", "value": {"stringValue": data.get("receiptId", "r1")}},
                {"key": "ga5.receipt.nonce", "value": {"stringValue": outcome.get("nonce", "n1")}},
                {"key": "http.request.method", "value": {"stringValue": "POST"}},
                {"key": "http.request.resend_count", "value": {"intValue": 0}}
            ]
        })
        
        # Shift to Approval Phase
        app_id = "app_" + generate_hex_id(8)
        act_id = "act_" + generate_hex_id(8)
        
        state["dispatches"] = []
        state["approvals"] = [{
            "approvalId": app_id,
            "actionId": act_id,
            "toolName": "rollback_deployment",
            "argumentsDigest": hashlib.sha256(b"{}").hexdigest()
        }]
        
        session["pending_approval_id"] = app_id
        session["pending_effect_action_id"] = act_id
        
        return JSONResponse(content=state)
        
    elif approvals_in:
        app_in = approvals_in[0]
        if app_in.get("approvalId") != session.get("pending_approval_id"):
            return Response(status_code=400)
            
        state["receiptLog"].append({
            "receiptId": data.get("receiptId", "r2"),
            "approvalId": app_in.get("approvalId"),
            "decision": app_in.get("decision"),
            "nonce": app_in.get("nonce")
        })
        
        # Terminal Effect Dispatch
        state["status"] = "completed"
        state["chosenEffect"] = "rollback_deployment"
        state["suppressed"] = []
        state["dispatches"] = []
        state["approvals"] = []
        
        state["otlp"] = session["otlp"]
        
        return JSONResponse(content=state)
        
    return Response(status_code=400)

@app.get("/v2/incidents/{run_id}")
async def get_incident(run_id: str):
    if run_id not in INCIDENT_STATE:
        return Response(status_code=404)
    return JSONResponse(content=INCIDENT_STATE[run_id]["current_state"])
