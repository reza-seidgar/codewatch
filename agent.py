# ============================================================
# 🔐 Security Scanner — LangGraph MVP
# Colab-Optimized Notebook
# الهام گرفته از Strix (github.com/usestrix/strix)
# ============================================================

from __future__ import annotations

# %%
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CELL 1 — Install Dependencies
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# !pip install -q langgraph langchain-core openai pydantic

print("✅ Dependencies ready")


# %%
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CELL 2 — Configuration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
import os

# ── پروژه‌ای که می‌خوای اسکن کنی ──
PROJECT_PATH = "/content/your_project"   # ← اینجا رو عوض کن

# ── LLM Provider ──
LLM_PROVIDER   = "gapgpt"               # "gapgpt" | "local" | "openai"
GAPGPT_API_KEY = "YOUR_API_KEY"         # ← کلید API
GAPGPT_MODEL   = "gpt-4o-mini"

LOCAL_BASE_URL = "http://localhost:11434"
LOCAL_MODEL    = "llama3"

print(f"✅ Config loaded — target: {PROJECT_PATH}")


# %%
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CELL 3 — Schemas & State
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
from enum import Enum
from typing import List, Optional, Any
from typing_extensions import TypedDict
from pydantic import BaseModel


class Language(str, Enum):
    CSHARP     = "csharp"
    PYTHON     = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA       = "java"
    GO         = "go"
    UNKNOWN    = "unknown"


class Framework(str, Enum):
    DOTNET      = "dotnet"
    DOTNET_WEBAPI = "dotnet_webapi"
    DJANGO      = "django"
    FASTAPI     = "fastapi"
    FLASK       = "flask"
    EXPRESS     = "express"
    NESTJS      = "nestjs"
    SPRING      = "spring"
    UNKNOWN     = "unknown"


class Priority(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    UNKNOWN  = "unknown"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class VulnerabilityPriority(BaseModel):
    vuln_type:      str
    priority:       Priority
    reason:         str
    relevant_files: List[str] = []   # ← orchestrator اینو پر می‌کنه


class Finding(BaseModel):
    vuln_type:    str
    severity:     Severity
    file_path:    str
    line_number:  Optional[int] = None
    description:  str
    code_snippet: Optional[str] = None
    confidence:   float         = 0.5    # 0.0–1.0
    detected_by:  str           = ""     # کدوم agent پیداش کرد


class ProjectAnalysis(BaseModel):
    language:       Language
    framework:      Framework
    dependencies:   List[str]
    entry_points:   List[str]
    analysis_notes: str


# ── LangGraph State ──
class SecurityScanState(TypedDict):
    project_path:     str
    scan_result:      dict
    project_analysis: Optional[ProjectAnalysis]
    vuln_priorities:  List[VulnerabilityPriority]
    findings:         List[Finding]
    agents_to_run:    List[str]
    completed_agents: List[str]
    current_agent:    Optional[str]
    errors:           List[str]
    final_report:     Optional[str]


print("✅ Schemas & State defined")


# %%
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CELL 4 — LLM Client
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
from openai import OpenAI


class LLMClient:
    def __init__(self, provider: str, api_key: str, model: str, base_url: str = None):
        if provider == "gapgpt":
            self.client = OpenAI(base_url="https://api.gapapi.com/v1", api_key=api_key)
        elif provider == "local":
            self.client = OpenAI(base_url=f"{base_url}/v1", api_key="not-needed")
        else:
            self.client = OpenAI(api_key=api_key)
        self.model = model

    def chat(self, messages: list, temperature: float = 0.1, max_tokens: int = 2048) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=False,
        )
        content = response.choices[0].message.content
        if not content or not content.strip():
            raise ValueError("Empty response from LLM")
        return content.strip()


# Initialize
if LLM_PROVIDER == "gapgpt":
    llm = LLMClient("gapgpt", GAPGPT_API_KEY, GAPGPT_MODEL)
elif LLM_PROVIDER == "local":
    llm = LLMClient("local", "x", LOCAL_MODEL, LOCAL_BASE_URL)
else:
    llm = LLMClient("openai", GAPGPT_API_KEY, GAPGPT_MODEL)

print(f"✅ LLM Client ready — model: {llm.model}")


# %%
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CELL 5 — Smart File Selector
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
نقطه کلیدی معماری:
به جای دادن ۵۰۰ فایل به LLM، برای هر vuln type
فقط فایل‌های مرتبط رو انتخاب می‌کنیم.

هر entry داره:
  extensions    — پسوند فایل‌های مرتبط
  path_keywords — کلمه در PATH (مثلاً "auth", "login")
  code_keywords — کلمه در محتوا (grep-like)
  max_files     — حداکثر فایل به LLM
"""
from pathlib import Path


VULN_PATTERNS = {
    "sql_injection": {
        "extensions":    ["py", "cs", "java", "js", "ts", "php", "go"],
        "path_keywords": ["model", "repo", "repository", "database", "db", "dal", "query", "store"],
        "code_keywords": ["SELECT", "INSERT", "UPDATE", "DELETE", "execute", "query",
                          "cursor", "raw(", "FromSqlRaw", "SqlCommand", "db.Query"],
        "max_files": 15,
    },
    "xss": {
        "extensions":    ["html", "js", "jsx", "ts", "tsx", "cshtml", "razor", "jinja", "jinja2"],
        "path_keywords": ["template", "view", "component", "page", "ui", "front"],
        "code_keywords": ["innerHTML", "dangerouslySetInnerHTML", "document.write",
                          "eval(", "v-html", "| safe", "mark_safe"],
        "max_files": 12,
    },
    "hardcoded_secrets": {
        "extensions":    ["py", "cs", "java", "js", "ts", "go", "env",
                          "json", "yaml", "yml", "config", "xml"],
        "path_keywords": ["config", "settings", "appsettings", "env", "secret",
                          "credential", "auth"],
        "code_keywords": ["password", "secret", "api_key", "apikey", "token",
                          "private_key", "ACCESS_KEY", "client_secret", "conn_str"],
        "max_files": 20,
    },
    "auth_bypass": {
        "extensions":    ["py", "cs", "java", "js", "ts", "go"],
        "path_keywords": ["auth", "login", "middleware", "guard", "filter",
                          "interceptor", "policy", "permission", "role"],
        "code_keywords": ["@login_required", "IsAuthenticated", "Bearer", "JWT",
                          "authorize", "[Authorize]", "verify_token", "check_permission"],
        "max_files": 12,
    },
    "idor": {
        "extensions":    ["py", "cs", "java", "js", "ts", "go"],
        "path_keywords": ["controller", "view", "api", "route", "endpoint", "handler"],
        "code_keywords": ["user_id", "userId", "owner", "request.user",
                          "current_user", "GetById", "FindById", "ObjectId"],
        "max_files": 15,
    },
    "ssrf": {
        "extensions":    ["py", "cs", "java", "js", "ts", "go"],
        "path_keywords": ["http", "client", "fetch", "request", "proxy", "webhook", "integration"],
        "code_keywords": ["requests.get", "requests.post", "HttpClient",
                          "fetch(", "axios", "urllib", "http.get", "url="],
        "max_files": 10,
    },
    "path_traversal": {
        "extensions":    ["py", "cs", "java", "js", "ts", "go", "php"],
        "path_keywords": ["file", "upload", "download", "static", "media", "storage"],
        "code_keywords": ["open(", "File.Read", "readFile", "sendFile",
                          "os.path", "Path(", "../", "file_path", "filename"],
        "max_files": 10,
    },
    "insecure_deserialization": {
        "extensions":    ["py", "cs", "java", "js", "ts"],
        "path_keywords": ["serial", "deserial", "model", "schema", "parser"],
        "code_keywords": ["pickle", "yaml.load", "json.loads", "deserialize",
                          "ObjectMapper", "JsonConvert", "fromJson"],
        "max_files": 10,
    },
}


def _path_matches(rel_path: str, keywords: list) -> bool:
    path_lower = rel_path.lower()
    return any(kw.lower() in path_lower for kw in keywords)


def _content_matches(abs_path: Path, keywords: list, max_bytes: int = 60_000) -> bool:
    try:
        text = abs_path.read_bytes()[:max_bytes].decode("utf-8", errors="ignore")
        return any(kw in text for kw in keywords)
    except Exception:
        return False


def select_files_for_vuln(vuln_type: str, scan_result: dict, project_path: str) -> List[str]:
    """برای یه vuln_type، فایل‌های مرتبط رو با scoring برمی‌گردونه."""
    if vuln_type not in VULN_PATTERNS:
        # fallback: همه فایل‌های کد اصلی (محدود)
        fallback = []
        for ext in ["py", "cs", "java", "js", "ts", "go"]:
            fallback.extend(scan_result.get("files_by_extension", {}).get(ext, [])[:5])
        return fallback[:20]

    pat = VULN_PATTERNS[vuln_type]
    root = Path(project_path)
    candidates = []   # (score, rel_path)

    for ext in pat["extensions"]:
        for rel in scan_result.get("files_by_extension", {}).get(ext, []):
            score = 0
            if _path_matches(rel, pat["path_keywords"]):
                score += 2
            abs_p = root / rel
            if abs_p.exists() and _content_matches(abs_p, pat["code_keywords"]):
                score += 3
            if score > 0:
                candidates.append((score, rel))

    candidates.sort(key=lambda x: x[0], reverse=True)
    return [p for _, p in candidates[: pat["max_files"]]]


def read_files_for_llm(
    file_paths: List[str],
    project_path: str,
    max_per_file: int = 2500,
    total_max: int = 25_000,
) -> str:
    """فایل‌های انتخاب شده رو می‌خونه و یه block متنی برای LLM می‌سازه."""
    root = Path(project_path)
    parts, total = [], 0

    for rel in file_paths:
        if total >= total_max:
            parts.append("\n[... بقیه فایل‌ها به علت محدودیت حجم حذف شدند ...]")
            break
        abs_p = root / rel
        if not abs_p.exists():
            continue
        try:
            content = abs_p.read_text(encoding="utf-8", errors="ignore")
            if len(content) > max_per_file:
                content = content[:max_per_file] + "\n... [truncated]"
            block = f"\n{'─'*50}\n📄 {rel}\n{'─'*50}\n{content}\n"
            parts.append(block)
            total += len(block)
        except Exception as e:
            parts.append(f"\n[❌ خطا: {rel} — {e}]")

    return "".join(parts) or "[هیچ فایل مرتبطی پیدا نشد]"


print("✅ Smart File Selector ready")


# %%
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CELL 6 — LangGraph Nodes
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
import re, json
from functools import partial


# ── JSON parser ──
def _parse_json(text: str) -> Any:
    text = re.sub(r"```json\s*|\s*```", "", text).strip()
    m = re.search(r"(\[|\{).*", text, re.DOTALL)
    if m:
        text = text[m.start():]
    return json.loads(text)


# ── Safe enum converters ──
def _lang(v):
    try: return Language(v.lower())
    except ValueError: return Language.UNKNOWN

def _fw(v):
    try: return Framework(v.lower())
    except ValueError: return Framework.UNKNOWN

def _pri(v):
    try: return Priority(v.lower())
    except ValueError: return Priority.UNKNOWN

def _sev(v):
    try: return Severity(v.lower())
    except ValueError: return Severity.MEDIUM


# ────────────────────────────────
# Node 1: Scanner
# ────────────────────────────────
IGNORE_DIRS = {
    "node_modules", ".venv", "venv", "__pycache__", ".git",
    "bin", "obj", "target", "build", "dist", ".idea", ".vscode",
    "Lib", "Scripts", "Include",
}
DEP_FILES = {
    "requirements.txt", "pyproject.toml", "package.json", "Pipfile",
    "pom.xml", "build.gradle", "go.mod", "Cargo.toml", "composer.json",
}


def scanner_node(state: SecurityScanState) -> dict:
    print("\n📂 [Scanner] اسکن ساختار پروژه...")
    root = Path(state["project_path"])

    if not root.exists():
        err = f"Path not found: {root}"
        print(f"   ❌ {err}")
        return {"errors": state.get("errors", []) + [err]}

    def ok(p: Path) -> bool:
        return all(part not in IGNORE_DIRS for part in p.parts) and p.name not in IGNORE_DIRS

    files_by_ext, config_files, dep_files = {}, [], {}
    total = 0

    for i, fp in enumerate(root.rglob("*")):
        if i >= 1000: break
        if not fp.is_file() or not ok(fp.relative_to(root)): continue
        total += 1
        ext = fp.suffix.lstrip(".").lower()
        rel = str(fp.relative_to(root))
        if ext:
            files_by_ext.setdefault(ext, []).append(rel)
        if fp.name in DEP_FILES or fp.suffix in [".csproj", ".sln"]:
            config_files.append(rel)
            try:
                dep_files[fp.name] = fp.read_text(encoding="utf-8", errors="ignore")[:5120]
            except Exception:
                pass

    print(f"   ✅ {total} فایل | {len(config_files)} config")

    return {
        "scan_result": {
            "files_by_extension":     {k: v[:30] for k, v in files_by_ext.items()},
            "config_files":           config_files,
            "total_files":            total,
            "dependency_files_content": dep_files,
        }
    }


# ────────────────────────────────
# Node 2: Orchestrator
# ────────────────────────────────

def orchestrator_node(state: SecurityScanState, llm: LLMClient) -> dict:
    """
    مغز متفکر:
     1. تحلیل language / framework
     2. اولویت‌بندی vuln ها
     3. انتخاب هوشمند فایل‌ها برای هر vuln
    """
    print("\n🧠 [Orchestrator] تحلیل پروژه...")
    scan = state["scan_result"]

    # Step 1 — Analyze structure
    prompt = f"""Analyze this codebase:
Total files: {scan['total_files']}
Extensions:  {', '.join(list(scan['files_by_extension'].keys())[:20])}
Config files: {', '.join(scan['config_files'][:10])}
"""
    for name, content in list(scan["dependency_files_content"].items())[:4]:
        prompt += f"\n--- {name} ---\n{content[:600]}\n"
    prompt += '\nReturn ONLY JSON: {"language":"...","framework":"...","dependencies":["..."],"entry_points":["..."],"analysis_notes":"..."}'

    raw = llm.chat(
        [{"role": "system", "content": "Code analysis expert. Return ONLY valid JSON."},
         {"role": "user",   "content": prompt}],
        temperature=0.1,
    )
    s = _parse_json(raw)
    analysis = ProjectAnalysis(
        language       = _lang(s.get("language", "unknown")),
        framework      = _fw(s.get("framework", "unknown")),
        dependencies   = s.get("dependencies", []),
        entry_points   = s.get("entry_points", []),
        analysis_notes = s.get("analysis_notes", ""),
    )
    print(f"   🎯 {analysis.language} / {analysis.framework}")

    # Step 2 — Prioritize vulnerabilities
    print("   📋 اولویت‌بندی آسیب‌پذیری‌ها...")
    vprompt = f"""OWASP security expert. Prioritize vulnerabilities for:
Language:     {analysis.language}
Framework:    {analysis.framework}
Dependencies: {', '.join(analysis.dependencies[:15])}

Return ONLY JSON array (5–8 items):
[{{"vuln_type":"sql_injection","priority":"critical","reason":"..."}}]

Allowed vuln_type values: sql_injection, xss, hardcoded_secrets, auth_bypass, idor, ssrf, path_traversal, insecure_deserialization
Allowed priority values:  critical, high, medium, low"""

    raw2 = llm.chat(
        [{"role": "system", "content": "Return ONLY a JSON array."},
         {"role": "user",   "content": vprompt}],
        temperature=0.2,
    )
    vulns_raw = _parse_json(raw2)

    # Step 3 — Smart file selection per vuln
    print("   📂 انتخاب فایل‌های مرتبط...")
    vuln_priorities, agents_to_run = [], []

    for v in vulns_raw:
        vtype = v.get("vuln_type", "unknown")
        files = select_files_for_vuln(vtype, scan, state["project_path"])
        vp = VulnerabilityPriority(
            vuln_type      = vtype,
            priority       = _pri(v.get("priority", "medium")),
            reason         = v.get("reason", ""),
            relevant_files = files,
        )
        vuln_priorities.append(vp)
        agents_to_run.append(vtype)
        print(f"      [{vp.priority:8}] {vtype:30} → {len(files)} فایل")

    return {
        "project_analysis": analysis,
        "vuln_priorities":  vuln_priorities,
        "agents_to_run":    agents_to_run,
        "completed_agents": [],
        "findings":         [],
    }


# ────────────────────────────────
# Node 3: Vulnerability Agent (sequential loop)
# ────────────────────────────────

AGENT_SYSTEM_PROMPTS = {
    "sql_injection": """You are a SQL injection detection specialist.

Your ONLY job: find lines where user input reaches a SQL query without parameterization.

Patterns to flag (language-specific):
- Python/sqlite3:   cursor.execute(f"...{var}...")  or  "SELECT..." % var  or  "SELECT..." + var
- Python/SQLAlchemy: db.execute(text(f"..."))  or  .filter(f"...")
- FastAPI + sqlite3: any f-string or .format() inside cursor.execute()
- Django:           raw(f"...")  or  extra(where=[f"..."])
- C#/.NET:          new SqlCommand("..." + var)  or  string.Format("SELECT...{0}", var)
- Java/JDBC:        statement.execute("SELECT..." + var)
- Node.js:          db.query(`SELECT...${var}`)

Severity rules:
- CRITICAL: query is in a login/auth endpoint OR returns sensitive data (passwords, tokens)
- HIGH:     query is in a data-retrieval endpoint with direct user input
- MEDIUM:   indirect user input, or filtered but still risky
- LOW:      very unlikely to be exploitable""",

    "xss": """You are an XSS detection specialist.

Your ONLY job: find lines where user input reaches HTML output without encoding.

Patterns to flag:
- JavaScript:  innerHTML = userInput,  document.write(userInput),  eval(userInput)
- React:       dangerouslySetInnerHTML={{ __html: userInput }}
- Vue:         v-html="userInput"
- Jinja2:      {{ var | safe }}  or  Markup(var)
- Django:      mark_safe(var)  or  {% autoescape off %}
- C# Razor:    @Html.Raw(var)

Severity rules:
- CRITICAL: XSS in authenticated area OR can steal session cookies
- HIGH:     reflected XSS with direct user input in response
- MEDIUM:   stored XSS with limited impact
- LOW:      self-XSS or very restricted context""",

    "hardcoded_secrets": """You are a hardcoded secrets detection specialist.

Your ONLY job: find actual secret values hardcoded in source files.

What to flag:
- Passwords assigned to variables: password = "abc123", PASSWORD = "secret"
- API keys: api_key = "sk-...", API_KEY = "AKIA..."
- Connection strings with credentials: "Server=...;Password=real_pass"
- Private keys or tokens inline in code

What NOT to flag:
- Placeholder strings: password = "YOUR_PASSWORD_HERE", api_key = "xxx"
- Empty strings: password = ""
- Variable references: password = os.getenv("PASSWORD")
- Test/example values that are obviously fake: password = "test", key = "dummy"

Severity rules:
- CRITICAL: admin/root credentials OR production API keys
- HIGH:     user credentials OR service account keys
- MEDIUM:   internal service passwords
- LOW:      test credentials that might be reused""",

    "auth_bypass": """You are an authentication bypass detection specialist.

Your ONLY job: find endpoints or functions missing proper authentication/authorization checks.

Patterns to flag:
- FastAPI: route without Depends(get_current_user) or equivalent
- Django:  view without @login_required or LoginRequiredMixin
- Express: route without passport/jwt middleware
- Spring:  endpoint without @PreAuthorize or security config exclusion
- General: JWT decoded but claims not verified, token presence checked but not validated

Severity rules:
- CRITICAL: admin functionality accessible without auth
- HIGH:     user data accessible without auth
- MEDIUM:   non-sensitive endpoint missing auth that should have it
- LOW:      optional auth endpoint with minor data exposure""",

    "idor": """You are an IDOR (Insecure Direct Object Reference) detection specialist.

Your ONLY job: find endpoints that retrieve/modify objects using IDs from user input
WITHOUT checking that the current user owns that object.

Pattern to flag:
  user_id = request.params["id"]      # from user
  obj = db.get(user_id)               # direct fetch
  return obj                          # NO ownership check between fetch and return

What NOT to flag if you see:
  if obj.owner_id != current_user.id: raise 403

Severity rules:
- CRITICAL: exposes or modifies other users' sensitive data (PII, financial)
- HIGH:     exposes other users' private data
- MEDIUM:   exposes non-sensitive but private data
- LOW:      very limited data exposure""",

    "ssrf": """You are an SSRF detection specialist.

Your ONLY job: find places where user-controlled input is used as a URL in an HTTP request.

Patterns to flag:
- Python:  requests.get(user_input),  urllib.request.urlopen(user_input)
- Node.js: fetch(req.body.url),  axios.get(req.query.url)
- Java:    new URL(userInput).openConnection()
- C#:      new HttpClient().GetAsync(userInput)

What makes it worse (raise severity):
- No URL validation before the request
- Can reach internal IPs (169.254.x.x, 10.x.x.x, localhost)
- Response is returned directly to user

Severity rules:
- CRITICAL: can reach internal metadata/cloud endpoints with no filtering
- HIGH:     can reach arbitrary external URLs, response returned to user
- MEDIUM:   user controls part of URL (path/query), host is fixed
- LOW:      very restricted URL usage""",

    "path_traversal": """You are a path traversal detection specialist.

Your ONLY job: find where user input is used to construct file paths without sanitization.

Patterns to flag:
- Python:  open(user_input),  Path(base) / user_input  without validation
- Node.js: fs.readFile(req.params.file),  path.join(base, userInput)
- Java:    new File(baseDir + userInput)
- C#:      File.ReadAllText(basePath + userInput)

Safe patterns (do NOT flag):
- os.path.basename(user_input) used before joining
- user_input validated against allowlist of filenames
- Path(base).resolve() checked to start with base

Severity rules:
- CRITICAL: can read /etc/passwd, source code, or config files
- HIGH:     arbitrary file read outside web root
- MEDIUM:   limited directory traversal
- LOW:      very restricted context""",

    "insecure_deserialization": """You are a deserialization security specialist.

Your ONLY job: find where untrusted data is deserialized with unsafe methods.

Patterns to flag:
- Python:  pickle.loads(user_data),  yaml.load(data) without Loader=yaml.SafeLoader
- Java:    ObjectInputStream.readObject() on untrusted data
- PHP:     unserialize(user_input)
- Node.js: serialize-javascript or node-serialize on untrusted input

Safe patterns (do NOT flag):
- json.loads() — JSON is safe
- yaml.safe_load() — safe
- pickle.loads() on data from trusted internal source

Severity rules:
- CRITICAL: untrusted network input deserialized with pickle/java.io
- HIGH:     yaml.load without SafeLoader on user input
- MEDIUM:   internal but unvalidated data
- LOW:      theoretical risk, very limited exposure""",
}

_DEFAULT_PROMPT = """You are a security code reviewer.
Find security vulnerabilities in the provided code.
Report only confirmed issues with clear evidence in the code."""

# ── Finding format — NO recommendation field ──
_FINDING_FORMAT = """
IMPORTANT RULES:
1. Only report findings where you can point to the EXACT vulnerable line
2. Do NOT report the same vulnerability twice for the same line
3. Do NOT include any fix or recommendation
4. Assign severity strictly based on the rules in your system prompt

Return ONLY a JSON array. If nothing found, return [].
Each item must have exactly these fields:
{
  "vuln_type":    "<string matching the vulnerability you were asked to check>",
  "severity":     "critical|high|medium|low",
  "file_path":    "relative/path/to/file.py",
  "line_number":  <integer, required — the exact vulnerable line>,
  "description":  "<one sentence: what is wrong and why it is dangerous>",
  "code_snippet": "<the exact vulnerable line or max 2 lines>",
  "confidence":   <float 0.0-1.0 based on how certain you are>
}"""


def vuln_agent_node(state: SecurityScanState, llm: LLMClient) -> dict:
    completed       = state.get("completed_agents", [])
    vuln_priorities = state.get("vuln_priorities", [])

    current_vp = next((vp for vp in vuln_priorities if vp.vuln_type not in completed), None)
    if not current_vp:
        return {}

    vtype    = current_vp.vuln_type
    analysis = state["project_analysis"]
    print(f"\n🔍 [{vtype.upper()} Agent]  priority={current_vp.priority}  files={len(current_vp.relevant_files)}")

    file_block = read_files_for_llm(
        current_vp.relevant_files,
        state["project_path"],
    )

    # ── Framework-aware context برای prompt ──
    framework_ctx = f"Language: {analysis.language} | Framework: {analysis.framework}"
    deps_ctx      = f"Key dependencies: {', '.join(analysis.dependencies[:10])}" if analysis.dependencies else ""

    user_prompt = f"""{framework_ctx}
{deps_ctx}
Checking for: {vtype}
Why flagged: {current_vp.reason}

Code to analyze:
{file_block}
{_FINDING_FORMAT}"""

    new_findings = []
    try:
        raw = llm.chat(
            [{"role": "system", "content": AGENT_SYSTEM_PROMPTS.get(vtype, _DEFAULT_PROMPT)},
             {"role": "user",   "content": user_prompt}],
            temperature=0.1,
            max_tokens=2048,
        )
        for f in _parse_json(raw):
            try:
                new_findings.append(Finding(
                    vuln_type    = f.get("vuln_type", vtype),
                    severity     = _sev(f.get("severity", "medium")),
                    file_path    = f.get("file_path", "unknown"),
                    line_number  = f.get("line_number"),
                    description  = f.get("description", ""),
                    code_snippet = f.get("code_snippet"),
                    confidence   = float(f.get("confidence", 0.5)),
                    detected_by  = vtype,
                ))
            except Exception as e:
                print(f"   ⚠️ finding parse error: {e}")
    except Exception as e:
        print(f"   ❌ agent error: {e}")
        return {
            "completed_agents": completed + [vtype],
            "errors": state.get("errors", []) + [f"{vtype}: {e}"],
        }

    print(f"   ✅ {len(new_findings)} یافته")
    return {
        "findings":         state.get("findings", []) + new_findings,
        "completed_agents": completed + [vtype],
        "current_agent":    vtype,
    }


# ────────────────────────────────
# Node 4: Aggregator
# ────────────────────────────────

def _deduplicate(findings: List[Finding]) -> List[Finding]:
    """
    چندین finding که به همون باگ اشاره دارن رو merge می‌کنه.

    منطق deduplication:
      key = (file_path, line_number, vuln_type_normalized)
      اگه چند finding همین key رو داشتن:
        → نگه‌دار اون که severity بالاتره
        → confidence رو max بگیر
        → detected_by هایشون رو merge کن
    """
    from collections import defaultdict

    SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    # normalize vuln_type: "Sql Injection" → "sql_injection"
    def norm_type(t: str) -> str:
        return t.lower().replace(" ", "_")

    # key: (file, line, vuln_type_normalized)
    # اگه line_number نداشت، از code_snippet اول ۴۰ کاراکتر استفاده می‌کنه
    def make_key(f: Finding) -> tuple:
        line = f.line_number if f.line_number is not None else hash(f.code_snippet or "")[:8]
        return (f.file_path, line, norm_type(f.vuln_type))

    groups: dict[tuple, list] = defaultdict(list)
    for f in findings:
        groups[make_key(f)].append(f)

    deduped = []
    for key, group in groups.items():
        # بهترین finding از نظر severity
        best = max(group, key=lambda x: SEV_RANK.get(x.severity.value, 0))
        # max confidence
        best_conf = max(g.confidence for g in group)
        # همه agent هایی که این رو پیدا کردن
        all_agents = list({g.detected_by for g in group if g.detected_by})

        deduped.append(Finding(
            vuln_type    = best.vuln_type,
            severity     = best.severity,
            file_path    = best.file_path,
            line_number  = best.line_number,
            description  = best.description,
            code_snippet = best.code_snippet,
            confidence   = best_conf,
            detected_by  = ", ".join(all_agents),
        ))

    # sort: severity desc، بعد confidence desc
    deduped.sort(
        key=lambda x: (SEV_RANK.get(x.severity.value, 0) * -1, x.confidence * -1)
    )
    return deduped


def aggregator_node(state: SecurityScanState, llm: LLMClient) -> dict:
    print("\n📊 [Aggregator] deduplication + تولید گزارش...")
    raw_findings = state.get("findings", [])
    analysis     = state.get("project_analysis")

    if not raw_findings:
        report = "✅ هیچ آسیب‌پذیری‌ای پیدا نشد."
        print(report)
        return {"final_report": report}

    # ── Deduplication ──
    findings = _deduplicate(raw_findings)
    removed  = len(raw_findings) - len(findings)
    print(f"   🧹 {len(raw_findings)} → {len(findings)} یافته (حذف {removed} duplicate)")

    by_sev = {s.value: [] for s in Severity}
    for f in findings:
        by_sev[f.severity.value].append(f)

    lines = [
        "# 🔐 Security Scan Report",
        "",
        f"**Project:** `{analysis.language} / {analysis.framework}`" if analysis else "",
        (
            f"**Findings:** {len(findings)}  |  "
            f"🔴 Critical: {len(by_sev['critical'])}  "
            f"🟠 High: {len(by_sev['high'])}  "
            f"🟡 Medium: {len(by_sev['medium'])}  "
            f"🟢 Low: {len(by_sev['low'])}"
        ),
        "",
        "---",
        "",
    ]

    icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}
    for sev in ["critical", "high", "medium", "low", "info"]:
        bucket = by_sev[sev]
        if not bucket:
            continue
        lines += [f"## {icons[sev]} {sev.upper()} ({len(bucket)})", ""]
        for i, f in enumerate(bucket, 1):
            title = f.vuln_type.replace("_", " ").title()
            loc   = f"`{f.file_path}`" + (f" · line **{f.line_number}**" if f.line_number else "")
            lines += [
                f"### {i}. {title}",
                f"**File:** {loc}",
                f"**Confidence:** {f.confidence:.0%}",
                "",
                f"{f.description}",
                f"```python\n{f.code_snippet}\n```" if f.code_snippet else "",
                "",
            ]

    report = "\n".join(lines)
    print(f"   ✅ گزارش نهایی آماده — {len(findings)} یافته منحصربه‌فرد")
    return {"final_report": report, "findings": findings}  # findings رو هم آپدیت کن


print("✅ All nodes defined")


# %%
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CELL 7 — Build LangGraph
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
from langgraph.graph import StateGraph, END


def _should_continue(state: SecurityScanState) -> str:
    """Conditional edge: آیا vuln agent باید دوباره اجرا بشه؟"""
    remaining = [
        a for a in state.get("agents_to_run", [])
        if a not in state.get("completed_agents", [])
    ]
    return "continue" if remaining else "done"


def build_graph(llm: LLMClient):
    g = StateGraph(SecurityScanState)

    g.add_node("scanner",      scanner_node)
    g.add_node("orchestrator", partial(orchestrator_node, llm=llm))
    g.add_node("vuln_agent",   partial(vuln_agent_node,   llm=llm))
    g.add_node("aggregator",   partial(aggregator_node,   llm=llm))

    g.set_entry_point("scanner")
    g.add_edge("scanner",      "orchestrator")
    g.add_edge("orchestrator", "vuln_agent")

    g.add_conditional_edges(
        "vuln_agent",
        _should_continue,
        {"continue": "vuln_agent", "done": "aggregator"},
    )
    g.add_edge("aggregator", END)

    return g.compile()


def run_sast(
    project_path: str,
    provider: str,
    api_key: str,
    model: str,
    local_base_url: str | None = None,
    local_model: str | None = None,
):
    """Run the SAST graph for the given project path using the agent's LLMClient.

    Returns the final state produced by the graph.
    """
    # Build agent-local LLM client (uses the same simple wrapper as the notebook)
    llm_local = LLMClient(provider, api_key, model, base_url=local_base_url)
    g = build_graph(llm_local)
    print("✅ LangGraph compiled")

    initial_state: SecurityScanState = {
        "project_path":     project_path,
        "scan_result":      {},
        "project_analysis": None,
        "vuln_priorities":  [],
        "findings":         [],
        "agents_to_run":    [],
        "completed_agents": [],
        "current_agent":    None,
        "errors":           [],
        "final_report":     None,
    }

    print(f"\n{'='*60}")
    print(f"🚀 Security Scanner — Starting")
    print(f"📁 Target: {project_path}")
    print(f"{'='*60}")

    final_state = g.invoke(initial_state)

    print(f"\n{'='*60}")
    print("✅ Scan complete")
    print(f"{'='*60}")

    return final_state


if __name__ == "__main__":
    # Run with the notebook config constants when executed directly
    final_state = run_sast(PROJECT_PATH, LLM_PROVIDER, GAPGPT_API_KEY, GAPGPT_MODEL, LOCAL_BASE_URL, LOCAL_MODEL)

    # Results & export (colab-style paths)
    import json
    try:
        from IPython.display import Markdown, display
    except Exception:
        Markdown = None
        display = None

    if final_state.get("final_report") and display:
        display(Markdown(final_state["final_report"]))

    if final_state.get("errors"):
        print("\n⚠️  Errors during scan:")
        for e in final_state["errors"]:
            print(f"   • {e}")

    output = {
        "project_analysis": (
            final_state["project_analysis"].model_dump()
            if final_state["project_analysis"] else None
        ),
        "total_raw_findings":  len(final_state.get("findings", [])),
        "findings": [f.model_dump() for f in final_state.get("findings", [])],
        "errors":   final_state.get("errors", []),
    }

    try:
        with open("/content/scan_result.json", "w", encoding="utf-8") as fp:
            json.dump(output, fp, indent=2, ensure_ascii=False)

        with open("/content/report.md", "w", encoding="utf-8") as fp:
            fp.write(final_state.get("final_report", "No report generated."))

        print("\n💾 فایل‌های ذخیره شده:")
        print("   /content/scan_result.json")
        print("   /content/report.md")
    except Exception:
        # Ignore write errors when not running in colab-style environment
        pass