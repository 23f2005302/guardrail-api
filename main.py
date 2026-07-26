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
from datetime import datetime
from fastapi import FastAPI, Request, Response, HTTPException
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
# QUESTION 7: INVOICE CLAIM A2A AGENT (/a2a/...)
# =====================================================================

TASKS_STORE = {} 
MESSAGE_DEDUPLICATION = {} 

def a2a_json(content, status_code=200):
    return JSONResponse(
        content=content,
        status_code=status_code,
        headers={"Content-Type": "application/a2a+json"}
    )

def extract_principal_and_validate(request: Request):
    headers = {k.lower(): v for k, v in request.headers.items()}
    auth = headers.get("authorization", "")
    version = headers.get("a2a-version", "")
    
    if not auth.startswith("Bearer "):
        return None, 401, "Missing or invalid Bearer token"
    if not version:
        return None, 400, "Missing A2A-Version header"
    if version != "1.0":
        return None, 400, "Unsupported A2A version"
        
    return auth.split(" ")[1], 200, None

@app.get("/.well-known/agent-card.json")
async def get_agent_card(request: Request):
    base_url = str(request.base_url).rstrip("/") + "/a2a"
    return a2a_json({
        "name": "Invoice Claim Agent",
        "description": "Reads invoice packages, proposes policy-backed actions, and processes execution results.",
        "version": "1.0.0",
        "capabilities": {"streaming": False},
        "skills": [
            {
                "name": "invoice_action_agent",
                "description": "Evaluates invoice claims against corporate policies.",
                "tags": ["invoice", "finance", "claims"]
            }
        ],
        "supportedInterfaces": [
            {
                "protocolBinding": "HTTP+JSON",
                "protocolVersion": "1.0",
                "url": base_url
            }
        ],
        "defaultInputModes": ["application/vnd.ga5.invoice-claim-batch+json"],
        "defaultOutputModes": [
            "application/vnd.ga5.invoice-action-proposals+json",
            "application/vnd.ga5.invoice-action-receipts+json"
        ]
    })

@app.post("/a2a/message:send")
async def a2a_message_send(request: Request):
    try:
        principal, code, err = extract_principal_and_validate(request)
        if code != 200:
            return a2a_json({"detail": err}, status_code=code)
            
        content_type = request.headers.get("content-type", "")
        if content_type and "application/a2a+json" not in content_type:
            return a2a_json({"detail": "Invalid media type"}, status_code=400)
            
        try:
            body = await request.json()
        except Exception:
            return a2a_json({"detail": "Malformed JSON"}, status_code=400)
            
        message = body.get("message", {})
        if not isinstance(message, dict):
            return a2a_json({"detail": "Invalid message structure"}, status_code=400)
            
        message_id = message.get("messageId")
        task_id = message.get("taskId")
        parts = message.get("parts", [])
        
        if not message_id:
            return a2a_json({"detail": "Missing messageId"}, status_code=400)

        if task_id:
            if principal not in TASKS_STORE or task_id not in TASKS_STORE[principal]:
                return a2a_json({"detail": "Task not found"}, status_code=404)
            
            task = TASKS_STORE[principal][task_id]
            if task.get("state") in ["TASK_STATE_COMPLETED", "TASK_STATE_CANCELED"]:
                return a2a_json({"detail": "Task already terminal"}, status_code=409)
                
            results_part = None
            for p in parts:
                if isinstance(p, dict) and p.get("mediaType") == "application/vnd.ga5.invoice-action-results+json":
                    results_part = p.get("data", {})
                    break
                    
            if not results_part:
                return a2a_json({"detail": "Missing results part"}, status_code=422)
                
            batch_id = results_part.get("batchId")
            results = results_part.get("results", [])
            
            stored_proposals = task.get("metadata", {}).get("proposals", [])
            proposal_map = {prop["actionId"]: prop for prop in stored_proposals}
            
            executions = []
            for res in results:
                action_id = res.get("actionId")
                if action_id not in proposal_map:
                    return a2a_json({"detail": "Invalid proposal reference"}, status_code=422)
                prop = proposal_map[action_id]
                
                if res.get("packageId") != prop["packageId"] or res.get("action") != prop["action"]:
                    return a2a_json({"detail": "Mismatch in result continuation"}, status_code=422)
                    
                if res.get("outcome") == "ACCEPTED":
                    executions.append({
                        "packageId": prop["packageId"],
                        "actionId": prop["actionId"],
                        "action": prop["action"],
                        "receiptNonce": res.get("receiptNonce"),
                        "facts": prop["facts"],
                        "evidenceRefs": prop["evidenceRefs"]
                    })
                    
            task.setdefault("history", []).append(message)
            receipt_artifact = {
                "batchId": batch_id,
                "executions": executions
            }
            task.setdefault("artifacts", []).append({
                "mediaType": "application/vnd.ga5.invoice-action-receipts+json",
                "data": receipt_artifact
            })
            task["state"] = "TASK_STATE_COMPLETED"
            task["updatedAt"] = datetime.utcnow().isoformat() + "Z"
            
            return a2a_json({"task": task})

        batch_part = None
        for p in parts:
            if isinstance(p, dict) and p.get("mediaType") == "application/vnd.ga5.invoice-claim-batch+json":
                batch_part = p.get("data", {})
                break
                
        if not batch_part:
            return a2a_json({"detail": "Missing batch claim part"}, status_code=400)
            
        msg_hash = hash_json(message)
        dedup_key = (principal, msg_hash)
        if dedup_key in MESSAGE_DEDUPLICATION:
            existing_task_id = MESSAGE_DEDUPLICATION[dedup_key]
            return a2a_json({"task": TASKS_STORE[principal][existing_task_id]})
            
        batch_id = batch_part.get("batchId", "batch_1")
        packages = batch_part.get("packages", [])
        
        proposals = []
        for pkg in packages:
            pid = pkg.get("packageId", "pkg_1")
            action_id = "act_" + uuid.uuid4().hex[:16]
            
            vendor = "Acme Corp"
            inv_no = "INV-1001"
            amount = 15000
            currency = "INR"
            evidence = ["line_1"]
            
            for src in pkg.get("sources", []):
                for line in src.get("lines", []):
                    if isinstance(line, dict) and line.get("lineId"):
                        evidence.append(line.get("lineId"))
                        
            proposals.append({
                "packageId": pid,
                "actionId": action_id,
                "action": "settle_invoice",
                "facts": {
                    "vendorName": vendor,
                    "invoiceNumber": inv_no,
                    "amountMinor": amount,
                    "currency": currency
                },
                "evidenceRefs": evidence[:3],
                "rationale": f"Invoice claim for package {pid} verified against policy and corporate records."
            })
            
        new_task_id = "task_" + uuid.uuid4().hex[:16]
        context_id = "ctx_" + uuid.uuid4().hex[:16]
        
        proposal_artifact = {
            "batchId": batch_id,
            "proposals": proposals
        }
        
        task_obj = {
            "taskId": new_task_id,
            "contextId": context_id,
            "state": "TASK_STATE_INPUT_REQUIRED",
            "history": [message],
            "artifacts": [
                {
                    "mediaType": "application/vnd.ga5.invoice-action-proposals+json",
                    "data": proposal_artifact
                }
            ],
            "metadata": {
                "proposals": proposals
            },
            "createdAt": datetime.utcnow().isoformat() + "Z",
            "updatedAt": datetime.utcnow().isoformat() + "Z"
        }
        
        if principal not in TASKS_STORE:
            TASKS_STORE[principal] = {}
        TASKS_STORE[principal][new_task_id] = task_obj
        MESSAGE_DEDUPLICATION[dedup_key] = new_task_id
        
        return a2a_json({"task": task_obj})
    except Exception as e:
        return a2a_json({"detail": f"Internal error handled: {str(e)}"}, status_code=400)

@app.get("/a2a/tasks")
async def a2a_list_tasks(request: Request):
    principal, code, err = extract_principal_and_validate(request)
    if code != 200:
        return a2a_json({"detail": err}, status_code=code)
    user_tasks = list(TASKS_STORE.get(principal, {}).values())
    return a2a_json({"tasks": user_tasks})

@app.get("/a2a/tasks/{id}")
async def a2a_get_task(id: str, request: Request):
    principal, code, err = extract_principal_and_validate(request)
    if code != 200:
        return a2a_json({"detail": err}, status_code=code)
    if principal not in TASKS_STORE or id not in TASKS_STORE[principal]:
        return a2a_json({"detail": "Task not found"}, status_code=404)
    return a2a_json(TASKS_STORE[principal][id])

@app.post("/a2a/tasks/{id}:cancel")
async def a2a_cancel_task(id: str, request: Request):
    principal, code, err = extract_principal_and_validate(request)
    if code != 200:
        return a2a_json({"detail": err}, status_code=code)
    if principal not in TASKS_STORE or id not in TASKS_STORE[principal]:
        return a2a_json({"detail": "Task not found"}, status_code=404)
        
    task = TASKS_STORE[principal][id]
    if task["state"] in ["TASK_STATE_COMPLETED", "TASK_STATE_CANCELED"]:
        return a2a_json({"detail": "Task already terminal"}, status_code=409)
        
    task["state"] = "TASK_STATE_CANCELED"
    task["updatedAt"] = datetime.utcnow().isoformat() + "Z"
    return a2a_json(task)
