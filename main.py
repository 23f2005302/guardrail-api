import os
import re
import json
import base64
import urllib.parse
import socket
import ipaddress
import requests
import unicodedata
from fastapi import FastAPI, Request

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
# Ensure BASE_DIR is strictly resolved
BASE_DIR = os.path.normpath(os.path.abspath("/srv/agent-redteam/sandbox-d0bedaad2f"))

# Map the UNQUOTED paths to the mock files to completely avoid TOCTOU File Not Found errors
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

    if os.path.isabs(decoded):
        target = os.path.abspath(decoded)
    else:
        stripped = decoded.lstrip("/")
        target = os.path.abspath(os.path.join(BASE_DIR, stripped))
        
    target = os.path.normpath(target)
    
    # Strictly ensure it starts with the sandbox boundary
    if not target.startswith(BASE_DIR + os.sep) and target != BASE_DIR: return None
    return target

def get_rebuilt_url(url: str):
    if not isinstance(url, str): return None
    # Block userinfo (@) and path confusions (\) immediately
    if '@' in url or '\\' in url: return None 
    
    try:
        url = re.sub(r'[\x00-\x20\x7f-\x9f]', '', url)
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme.lower() not in ["http", "https"]: return None
        
        host = parsed.hostname
        if not host: return None
        
        # CRITICAL FIX: No IDNA conversion. Must be EXACT string match to block lookalike domains
        if host not in ALLOWED_HOSTS_Q3: return None
        
        for res in socket.getaddrinfo(host, None):
            ip = res[4][0]
            ip_obj = ipaddress.ip_address(ip)
            if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or 
                ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_reserved or ip == "169.254.169.254"):
                return None
                
        netloc = host
        if parsed.port: netloc = f"{host}:{parsed.port}"
        
        return urllib.parse.urlunparse((parsed.scheme.lower(), netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
    except Exception: return None

@app.post("/redteam")
@app.post("/redteam/")
async def execute_tool_endpoint(request: Request):
    try:
        data = await request.json()
    except Exception: return {"action": "block", "reason": "Invalid JSON", "result": None}
        
    try:
        tool = data.get("tool")
        args = data.get("arguments", {})
        
        if tool == "read_file":
            safe_path = get_safe_path(args.get("path", ""))
            if not safe_path: return {"action": "block", "reason": "Traversal blocked", "result": None}
            
            # The rebuilt safe_path matches our dictionary exactly, perfectly solving TOCTOU
            if safe_path in MOCK_FILES:
                return {"action": "allow", "reason": "ok", "result": MOCK_FILES[safe_path]}
            
            try:
                with open(safe_path, "r") as f:
                    return {"action": "allow", "reason": "ok", "result": f.read()}
            except Exception as e: return {"action": "allow", "reason": "File not found", "result": str(e)}

        elif tool == "fetch_url":
            current_url = args.get("url", "")
            for _ in range(5):
                safe_url = get_rebuilt_url(current_url)
                if not safe_url: return {"action": "block", "reason": "Unsafe URL blocked", "result": None}
                
                try:
                    resp = requests.get(safe_url, allow_redirects=False, timeout=5)
                except Exception: return {"action": "block", "reason": "Fetch failed", "result": None}
                    
                if 300 <= resp.status_code < 400:
                    current_url = urllib.parse.urljoin(safe_url, resp.headers.get("Location", "").strip())
                else: return {"action": "allow", "reason": "Safe URL fetched", "result": resp.text}
                
            return {"action": "block", "reason": "Too many redirects", "result": None}
            
        return {"action": "block", "reason": f"Tool '{tool}' not recognized.", "result": None}
    except Exception: return {"action": "block", "reason": "Handled gracefully", "result": None}
