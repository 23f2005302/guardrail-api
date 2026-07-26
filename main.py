from fastapi import FastAPI, Request
import urllib.parse
import os
import re
import base64

app = FastAPI()

def check_http_request(url: str):
    """
    Blocks any HTTP request that isn't exactly registry.npmjs.org or pypi.org.
    Catches subdomain tricks like registry.npmjs.org.evil.com.
    """
    try:
        # Parse the URL to reliably extract just the hostname
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        
        # Exact match required
        if host in ["registry.npmjs.org", "pypi.org"]:
            return True, "Host is allowed."
        return False, f"Host '{host}' is strictly forbidden."
    except Exception:
        return False, "Invalid URL structure."

def check_write_file(path: str):
    """
    Ensures files are ONLY written inside /workspace/output/ or /home/agent/workspace/output/
    Prevents path traversal like /workspace/output/../../etc/shadow
    """
    # If the path is relative, assume it starts from the agent's working directory
    if not os.path.isabs(path):
        path = os.path.join("/home/agent/workspace", path)
        
    # normpath resolves any ".." or "." in the path
    normalized = os.path.normpath(path)
    
    # Check if the resolved path safely lives inside the allowed directories
    if normalized == "/workspace/output" or normalized.startswith("/workspace/output/"):
        return True, "Safe write path."
    if normalized == "/home/agent/workspace/output" or normalized.startswith("/home/agent/workspace/output/"):
        return True, "Safe write path."
        
    return False, "Write attempt outside of the allowed output directory."

def check_bash(command: str):
    """
    Blocks attempts to read the restricted credentials.env file.
    Includes checks for base64 wrapping, string splitting, and wildcards.
    """
    # 1. Decode potential hex (\x63) or octal (\143) characters used to hide strings
    cmd = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), command)
    cmd = re.sub(r'\\([0-7]{1,3})', lambda m: chr(int(m.group(1), 8)), cmd)
    
    # 2. Strip all quotes and backslashes (cat "cred"enti\als.env -> cat credentials.env)
    clean_cmd = re.sub(r'["\'\\]', '', cmd)
    
    # 3. Direct string match (and a check for reverse strings like env.slaitnederc)
    if "credentials.env" in clean_cmd or "vne.slaitnederc" in clean_cmd:
        return False, "Direct or reversed reference to credentials.env blocked."
        
    # 4. Block wildcards targeting the agent's sensitive directories (e.g., cat /home/agent/*)
    # This prevents using cat /home/agent/c* to read the file without typing its name
    if re.search(r'(?:/home/agent|~|\$HOME)[/\\][^\s]*[*?]', clean_cmd):
        return False, "Wildcards inside sensitive home directories are blocked."
        
    # 5. Search for Base64 and Hex wrapped commands
    words = re.findall(r'[A-Za-z0-9+/=]+', command)
    for word in words:
        # Check Base64 (e.g. Y3JlZGVudGlhbHMuZW52)
        if len(word) >= 16:
            try:
                decoded = base64.b64decode(word).decode('utf-8', errors='ignore')
                dec_clean = re.sub(r'["\'\\]', '', decoded)
                if "credentials.env" in dec_clean:
                    return False, "Base64 obfuscated payload blocked."
            except Exception:
                pass
                
        # Check Hex (e.g. 63726564656e7469616c732e656e76)
        if len(word) >= 20 and re.fullmatch(r'[0-9a-fA-F]+', word):
            try:
                decoded = bytes.fromhex(word).decode('utf-8', errors='ignore')
                dec_clean = re.sub(r'["\'\\]', '', decoded)
                if "credentials.env" in dec_clean:
                    return False, "Hex obfuscated payload blocked."
            except Exception:
                pass

    return True, "Bash command appears safe."

@app.post("/")
async def guardrail_endpoint(request: Request):
    """
    The main hook that the Agent Harness calls before executing a tool.
    """
    data = await request.json()
    tool = data.get("tool")
    
    allow = False
    reason = "Unknown error"
    
    # Route the request to the appropriate checker based on the tool
    if tool == "http_request":
        url = data.get("url", "")
        allow, reason = check_http_request(url)
        
    elif tool == "write_file":
        path = data.get("path", "")
        allow, reason = check_write_file(path)
        
    elif tool == "bash":
        command = data.get("command", "")
        allow, reason = check_bash(command)
        
    else:
        allow, reason = False, f"Tool '{tool}' is not supported."

    # Return the exact strict JSON format required by the grader
    return {
        "decision": "allow" if allow else "block",
        "reason": reason
    }