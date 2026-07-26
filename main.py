import os
import re
import json
import base64
import urllib.parse
from fastapi import FastAPI, Request

app = FastAPI()

# =====================================================================
# QUESTION 1: PRE-TOOL SECURITY GUARDRAIL
# =====================================================================

def check_http_request(url: str):
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
async def secure_guard_endpoint(request: Request):
    data = await request.json()
    tool = data.get("tool")
    
    allow = False
    reason = "Unknown error"
    
    if tool == "http_request":
        allow, reason = check_http_request(data.get("url", ""))
    elif tool == "write_file":
        allow, reason = check_write_file(data.get("path", ""))
    elif tool == "bash":
        allow, reason = check_bash(data.get("command", ""))
    else:
        allow, reason = False, f"Tool '{tool}' is not supported."

    return {
        "decision": "allow" if allow else "block",
        "reason": reason
    }


# =====================================================================
# QUESTION 2: RUN-CONTROL & LOOP GUARDRAIL
# =====================================================================

def normalize_value(val):
    if isinstance(val, dict):
        return {
            k: normalize_value(v)
            for k, v in sorted(val.items())
            if k != "trace_id"
        }
    elif isinstance(val, list):
        return [normalize_value(x) for x in val]
    elif isinstance(val, str):
        return re.sub(r'\s+', ' ', val).strip()
    else:
        return val

@app.post("/run-guard")
async def run_guard_endpoint(request: Request):
    data = await request.json()
    
    budget_tokens = data.get("budget_tokens", 42000)
    steps = data.get("steps", [])

    # 1. Budget Check
    total_tokens_used = sum(step.get("tokens_used", 0) for step in steps)
    if total_tokens_used >= budget_tokens:
        return {
            "decision": "halt",
            "reason": f"Cumulative tokens_used ({total_tokens_used}) reached budget ({budget_tokens})."
        }

    # 2. Canonicalize Steps
    signatures = []
    for step in steps:
        tool_name = step.get("tool", "")
        norm_args = normalize_value(step.get("args", {}))
        sig = (tool_name, json.dumps(norm_args, sort_keys=True))
        signatures.append(sig)

    # 3. Loop Rule: 3 in a row
    if len(signatures) >= 3:
        if signatures[-1] == signatures[-2] == signatures[-3]:
            return {
                "decision": "halt",
                "reason": "Loop detected: tool called 3 or more times consecutively with identical arguments."
            }

    # 4. Loop Rule: 2-step cycle
    if len(signatures) >= 6:
        if (signatures[-6] == signatures[-4] == signatures[-2]) and \
           (signatures[-5] == signatures[-3] == signatures[-1]):
            return {
                "decision": "halt",
                "reason": "Loop detected: 2-step alternating pattern."
            }

    # 5. Default Allow
    return {
        "decision": "continue",
        "reason": "Well under budget and no execution loop detected."
    }
