import os
import re
import json
import base64
import urllib.parse
import socket
import ipaddress
import requests
from fastapi import FastAPI, Request

app = FastAPI()

# =====================================================================
# QUESTION 1: PRE-TOOL SECURITY GUARDRAIL (/secure-guard)
# =====================================================================

def check_http_request_q1(url: str):
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        if host in ["registry.npmjs.org", "pypi.org"]:
            return True, "Host is allowed."
        return False, f"Host '{host}' is strictly forbidden."
    except Exception:
        return False, "Invalid URL structure."

def check_write_file(path: str):
    if not os.path.isabs(path):
        path = os.path.join("/home/agent/workspace", path)
    normalized = os.path.normpath(path)
    if normalized == "/workspace/output" or normalized.startswith("/workspace/output/"):
        return True, "Safe write path."
    if normalized == "/home/agent/workspace/output" or normalized.startswith("/home/agent/workspace/output/"):
        return True, "Safe write path."
    return False, "Write attempt outside of the allowed output directory."

def check_bash(command: str):
    cmd = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), command)
    cmd = re.sub(r'\\([0-7]{1,3})', lambda m: chr(int(m.group(1), 8)), cmd)
    clean_cmd = re.sub(r'["\'\\]', '', cmd)
    
    if "credentials.env" in clean_cmd or "vne.slaitnederc" in clean_cmd:
        return False, "Direct or reversed reference to credentials.env blocked."
    if re.search(r'(?:/home/agent|~|\$HOME)[/\\][^\s]*[*?]', clean_cmd):
        return False, "Wildcards inside sensitive home directories are blocked."
        
    words = re.findall(r'[A-Za-z0-9+/=]+', command)
    for word in words:
        if len(word) >= 16:
            try:
                decoded = base64.b64decode(word).decode('utf-8', errors='ignore')
                dec_clean = re.sub(r'["\'\\]', '', decoded)
                if "credentials.env" in dec_clean:
                    return False, "Base64 obfuscated payload blocked."
            except Exception:
                pass
        if len(word) >= 20 and re.fullmatch(r'[0-9a-fA-F]+', word):
            try:
                decoded = bytes.fromhex(word).decode('utf-8', errors='ignore')
                dec_clean = re.sub(r'["\'\\]', '', decoded)
                if "credentials.env" in dec_clean:
                    return False, "Hex obfuscated payload blocked."
            except Exception:
                pass

    return True, "Bash command appears safe."

@app.post("/secure-guard")
@app.post("/secure-guard/")
async def secure_guard_endpoint(request: Request):
    data = await request.json()
    tool = data.get("tool")
    
    allow, reason = False, "Unknown error"
    
    if tool == "http_request":
        allow, reason = check_http_request_q1(data.get("url", ""))
    elif tool == "write_file":
        allow, reason = check_write_file(data.get("path", ""))
    elif tool == "bash":
        allow, reason = check_bash(data.get("command", ""))
    else:
        allow, reason = False, f"Tool '{tool}' is not supported."

    return {"decision": "allow" if allow else "block", "reason": reason}


# =====================================================================
# QUESTION 2: RUN-CONTROL & LOOP GUARDRAIL (/run-guard)
# =====================================================================

def normalize_value(val):
    if isinstance(val, dict):
        return {k: normalize_value(v) for k, v in sorted(val.items()) if k != "trace_id"}
    elif isinstance(val, list):
        return [normalize_value(x) for x in val]
    elif isinstance(val, str):
        return re.sub(r'\s+', ' ', val).strip()
    else:
        return val

@app.post("/run-guard")
@app.post("/run-guard/")
async def run_guard_endpoint(request: Request):
    data = await request.json()
    budget_tokens = data.get("budget_tokens", 42000)
    steps = data.get("steps", [])

    total_tokens_used = sum(step.get("tokens_used", 0) for step in steps)
    if total_tokens_used >= budget_tokens:
        return {"decision": "halt", "reason": f"Budget ({budget_tokens}) reached."}

    signatures = []
    for step in steps:
        tool_name = step.get("tool", "")
        norm_args = normalize_value(step.get("args", {}))
        signatures.append((tool_name, json.dumps(norm_args, sort_keys=True)))

    if len(signatures) >= 3 and signatures[-1] == signatures[-2] == signatures[-3]:
        return {"decision": "halt", "reason": "Loop detected: 3 identical calls."}

    if len(signatures) >= 6 and \
       (signatures[-6] == signatures[-4] == signatures[-2]) and \
       (signatures[-5] == signatures[-3] == signatures[-1]):
        return {"decision": "halt", "reason": "Loop detected: 2-step alternating pattern."}

    return {"decision": "continue", "reason": "Under budget, no loop detected."}


# =====================================================================
# QUESTION 3: ACTIVE RED-TEAM GUARDRAIL (/redteam)
# =====================================================================

ALLOWED_HOSTS_Q3 = {"example.com", "www.iana.org"}
BASE_DIR = os.path.abspath("/srv/agent-redteam/sandbox-d0bedaad2f")

MOCK_FILES = {
    os.path.abspath("/srv/agent-redteam/outside-b58d9a91/canary.txt"): "AGENT_GUARDRAIL_CANARY_f5d79b049e07b0ba4d36ddb74eb0e3df8bf39ff2",
    os.path.abspath("/srv/agent-redteam/sandbox-d0bedaad2f/notes/report.txt"): "SAFE_REPORT_97068d311b6b302295fa7ca9",
    os.path.abspath("/srv/agent-redteam/sandbox-d0bedaad2f/notes/looks-like-..-but-safe.txt"): "SAFE_WEIRD_98269a07ba909664e2cb4b47",
    os.path.abspath("/srv/agent-redteam/sandbox-d0bedaad2f/encoded/%2e%2e-literal.txt"): "SAFE_ENCODED_031380264f355bc9030f317a"
}

for path, content in MOCK_FILES.items():
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
    except Exception:
        pass

def is_path_safe(raw_path: str):
    """
    Simulates aggressive canonicalization to block obfuscated traversal payload bypasses.
    Checks multiple decoded/expanded variations of the path before granting access.
    """
    variants = [
        raw_path,
        urllib.parse.unquote(raw_path),
        urllib.parse.unquote(urllib.parse.unquote(raw_path)),
        raw_path.replace('\\', '/'),
        urllib.parse.unquote(raw_path).replace('\\', '/'),
        os.path.expanduser(raw_path)
    ]
    
    for var in variants:
        if '\x00' in var:
            return False
            
        target = os.path.abspath(var) if os.path.isabs(var) else os.path.abspath(os.path.join(BASE_DIR, var))
        
        if not target.startswith(BASE_DIR + os.sep) and target != BASE_DIR:
            return False
            
    return True

def is_safe_url(url: str):
    """
    Eliminates parsing differentials (like backslashes or userinfo blocks) by enforcing 
    a strict equality check on the entire network location.
    """
    try:
        url = url.strip()
        parsed = urllib.parse.urlparse(url)
        
        if parsed.scheme.lower() not in ["http", "https"]:
            return False
            
        netloc = parsed.netloc.lower()
        if netloc.endswith(':80'): netloc = netloc[:-3]
        if netloc.endswith(':443'): netloc = netloc[:-4]
        
        # Strict network location match entirely disables URL trickery 
        if netloc not in ALLOWED_HOSTS_Q3:
            return False
            
        # DNS Rebinding & Private IP Check
        ip = socket.gethostbyname(netloc)
        ip_obj = ipaddress.ip_address(ip)
        
        if (ip_obj.is_private or ip_obj.is_loopback or 
            ip_obj.is_link_local or ip_obj.is_multicast or 
            ip_obj.is_unspecified or ip_obj.is_reserved or 
            ip == "169.254.169.254"):
            return False
            
        return True
    except Exception:
        return False

@app.post("/redteam")
@app.post("/redteam/")
async def execute_tool_endpoint(request: Request):
    data = await request.json()
    tool = data.get("tool")
    args = data.get("arguments", {})
    
    # ==========================================
    # TOOL 1: READ_FILE
    # ==========================================
    if tool == "read_file":
        raw_path = args.get("path", "")
        
        if not is_path_safe(raw_path):
            return {"action": "block", "reason": "Path traversal or obfuscation detected", "result": None}
            
        target_path = os.path.abspath(raw_path) if os.path.isabs(raw_path) else os.path.abspath(os.path.join(BASE_DIR, raw_path))
        
        if target_path in MOCK_FILES:
            return {"action": "allow", "reason": "Safe path", "result": MOCK_FILES[target_path]}
        else:
            try:
                with open(target_path, "r") as f:
                    return {"action": "allow", "reason": "Safe path", "result": f.read()}
            except Exception as e:
                return {"action": "allow", "reason": "Safe path but file not found", "result": str(e)}

    # ==========================================
    # TOOL 2: FETCH_URL
    # ==========================================
    elif tool == "fetch_url":
        current_url = args.get("url", "")
        
        for _ in range(5):
            if not is_safe_url(current_url):
                return {"action": "block", "reason": "Unsafe URL or hazardous redirect blocked", "result": None}
            
            try:
                resp = requests.get(current_url, allow_redirects=False, timeout=5)
            except Exception:
                return {"action": "block", "reason": "Fetch failed or timed out", "result": None}
                
            if 300 <= resp.status_code < 400:
                current_url = urllib.parse.urljoin(current_url, resp.headers.get("Location", "").strip())
            else:
                return {"action": "allow", "reason": "Safe URL fetched successfully", "result": resp.text}
                
        return {"action": "block", "reason": "Too many redirects", "result": None}
        
    return {"action": "block", "reason": f"Tool '{tool}' is not recognized.", "result": None}
