"""Analyzer Agent using a LangGraph-like workflow.

This module provides a sequential implementation of the requested nodes:
- scan_files_node
- analyze_with_llm_node
- prioritize_vulnerabilities_node
- build_final_analysis_node

Rather than depending on a specific version of langgraph at runtime, the
`build_analyzer_graph` function returns a small self-contained workflow object
with an `execute(state)` coroutine that runs the nodes in sequence, honoring
`should_continue` between steps. This keeps the behavior explicit and testable.
"""
from __future__ import annotations

import json
import re
import asyncio
from typing import TypedDict, Annotated, Any, List
import operator
from functools import partial

from app.agents.schemas import ProjectAnalysis, VulnerabilityPriority, VulnerabilityType, Priority
from app.agents.tools.file_scanner import scan_project_structure
from app.core.llm_client import LLMClient


# --- State تعریف ---
class AnalyzerState(TypedDict, total=False):
    project_path: str
    scan_result: dict
    llm_analysis: str
    llm_parsed: Any | None
    vuln_priorities: list[dict]
    final_analysis: ProjectAnalysis | None
    error: str | None
    messages: Annotated[List[str], operator.add]


def parse_json_safe(text: str) -> Any:
    """
    Try to robustly parse JSON returned by LLMs that may include markdown
    or stray text. Strategy:
    - Strip triple-backtick code fences
    - Try json.loads directly
    - If that fails, search for the first JSON object or array with regex and parse it
    - Raise ValueError if no JSON found or parsing fails
    """
    if not text:
        raise ValueError("Empty text")

    # Remove Markdown code fences ```json ... ``` or ``` ... ```
    text = re.sub(r"```(?:json)?\n", "", text)
    text = text.replace("```", "")

    # Trim surrounding whitespace
    s = text.strip()

    # Try direct parse
    try:
        return json.loads(s)
    except Exception:
        pass

    # Find an object or array using a simple balanced-brace regex (greedy-ish)
    # First try an object
    obj_match = re.search(r"(\{(?:.|\n)*\})", s)
    if obj_match:
        candidate = obj_match.group(1)
        try:
            return json.loads(candidate)
        except Exception:
            pass

    arr_match = re.search(r"(\[(?:.|\n)*\])", s)
    if arr_match:
        candidate = arr_match.group(1)
        try:
            return json.loads(candidate)
        except Exception:
            pass

    # Nothing worked
    raise ValueError("Could not parse JSON from LLM output")


# --- Node ها ---
def scan_files_node(state: AnalyzerState) -> AnalyzerState:
    """
    Node 1: اسکن فایل‌های پروژه (بدون LLM)
    scan_project_structure رو صدا میزنه
    نتیجه رو در state.scan_result ذخیره میکنه
    """
    try:
        project_path = state.get("project_path")
        if not project_path:
            raise ValueError("project_path is required")
        result = scan_project_structure(project_path)
        # Limit processed files to max 500 entries overall (keep structure)
        from itertools import islice

        limited_files = {}
        count = 0
        for ext, files in result.get("files_by_extension", {}).items():
            if count >= 500:
                break
            take = []
            for f in files:
                if count >= 500:
                    break
                take.append(f)
                count += 1
            if take:
                limited_files[ext] = take
        result["files_by_extension"] = limited_files
        state["scan_result"] = result
        state.setdefault("messages", []).append("scanned project files")
        return state
    except Exception as exc:
        state["error"] = f"scan_files_node error: {exc}"
        return state


async def analyze_with_llm_node(state: AnalyzerState, llm_client: LLMClient) -> AnalyzerState:
    """
    Node 2: تحلیل با LLM
    Calls LLMClient.chat and stores raw LLM response in state.llm_analysis
    Expects the LLM to return pure JSON as specified in the docstring.
    """
    try:
        scan = state.get("scan_result") or {}
        directory_tree = scan.get("directory_tree", "")
        config_files = scan.get("config_files", [])
        dependency_files = scan.get("dependency_files_content", {})

        system_prompt = (
            "You are a senior security engineer analyzing a software project.\n"
            "Analyze the provided project structure and return ONLY a valid JSON object as described."
        )

        user_prompt_parts = [
            "Directory tree:\n", directory_tree, "\n",
            "Config files:\n", json.dumps(config_files, indent=2), "\n",
            "Dependency files content:\n", json.dumps(dependency_files, indent=2), "\n",
            "Please determine: language, framework, dependencies (list), entry_points (list of relative paths), and analysis_notes.\n",
            "Return ONLY a JSON object exactly matching the format: {\n  \"language\": ..., \"framework\": ..., \"dependencies\": [...], \"entry_points\": [...], \"analysis_notes\": \"...\"\n}\n",
            "Do not include markdown or any commentary."
        ]
        user_prompt = "\n".join(user_prompt_parts)

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        # Debug logs requested by user
        try:
            print("🔍 DEBUG: Sending prompt to LLM")
            print(f"📏 System prompt length: {len(system_prompt)} chars")
            print(f"📏 User prompt length: {len(user_prompt)} chars")
            print(f"📝 First 300 chars of user prompt:\n{user_prompt[:300]}\n")
        except Exception:
            # Never fail because of logging
            pass

        # Call LLM with a timeout
        try:
            raw = await asyncio.wait_for(
                llm_client.chat(messages=messages, temperature=0.2, max_tokens=2048),
                timeout=120,
            )
        except Exception as exc:
            # Surface the exception in state
            state["error"] = f"analyze_with_llm_node error: {exc}"
            print(f"❌ ERROR in analyze_with_llm_node during chat call: {exc}")
            return state

        # Debug response
        try:
            print(f"✅ LLM Response length: {len(raw)} chars")
            print(f"📝 First 500 chars of response:\n{raw[:500]}\n")
        except Exception:
            pass

        # Empty response check
        if not raw or not str(raw).strip():
            err = ValueError("Empty response from LLM")
            state["error"] = f"analyze_with_llm_node error: {err}"
            print(f"❌ ERROR in analyze_with_llm_node: {err}")
            return state

        # Store raw text
        state["llm_analysis"] = raw
        # Try to parse/repair JSON safely and store parsed form
        try:
            parsed = parse_json_safe(raw)
            state["llm_parsed"] = parsed
        except Exception as parse_exc:
            # keep raw only; parsing will be attempted later
            state["llm_parsed"] = None
            print(f"⚠️ parse_json_safe failed: {parse_exc}")

        state.setdefault("messages", []).append("llm_analysis_received")
        return state
    except Exception as exc:
        state["error"] = f"analyze_with_llm_node error: {exc}"
        return state


async def prioritize_vulnerabilities_node(state: AnalyzerState, llm_client: LLMClient) -> AnalyzerState:
    """
    Node 3: اولویت‌بندی آسیب‌پذیری‌ها

    Uses state.llm_analysis as context and asks LLM to return a JSON array
    of vulnerability objects with fields: vuln_type, priority, reason.
    """
    try:
        llm_analysis = state.get("llm_analysis") or ""
        system_prompt = (
            "You are an OWASP security expert. Based on the project analysis, "
            "prioritize which vulnerability types to check. Return ONLY a valid JSON array."
        )
        user_prompt = (
            "Project analysis (from previous step):\n"
            f"{llm_analysis}\n\n"
            "Return a JSON array of objects with keys: vuln_type (one of the allowed types), priority (critical|high|medium|low), and reason.\n"
            "Example: [{\"vuln_type\": \"sql_injection\", \"priority\": \"critical\", \"reason\": \"...\"}]\n"
            "Do not include markdown or commentary."
        )
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        raw = await asyncio.wait_for(
            llm_client.chat(messages=messages, temperature=0.0, max_tokens=512),
            timeout=120,
        )
        try:
            parsed = parse_json_safe(raw)
        except Exception as exc:
            raise
        if not isinstance(parsed, list):
            raise ValueError("Expected a JSON array from vulnerability prioritization")
        # Validate items
        valid_types = {t.value for t in VulnerabilityType}
        valid_priorities = {p.value for p in Priority}
        cleaned: List[dict] = []
        for item in parsed:
            vt = item.get("vuln_type")
            pr = item.get("priority")
            reason = item.get("reason", "")
            if vt not in valid_types:
                # skip unknown types
                continue
            if pr not in valid_priorities:
                pr = "low"
            cleaned.append({"vuln_type": vt, "priority": pr, "reason": reason})

        state["vuln_priorities"] = cleaned
        state.setdefault("messages", []).append("vuln_priorities_received")
        return state
    except Exception as exc:
        state["error"] = f"prioritize_vulnerabilities_node error: {exc}"
        return state


def build_final_analysis_node(state: AnalyzerState) -> AnalyzerState:
    """
    Node 4: ساخت ProjectAnalysis از state
    JSON های llm رو parse میکنه
    ProjectAnalysis object میسازه
    در صورت خطا در parse، error رو در state.error ذخیره میکنه
    """
    try:
        raw = state.get("llm_analysis")
        if not raw:
            raise ValueError("No llm_analysis available to build final analysis")
        parsed = state.get("llm_parsed")
        if parsed is None:
            # try to parse raw as fallback
            parsed = parse_json_safe(raw)
        # Extract fields
        language = parsed.get("language", "unknown")
        framework = parsed.get("framework", "unknown")
        dependencies = parsed.get("dependencies", []) or []
        entry_points = parsed.get("entry_points", []) or []
        analysis_notes = parsed.get("analysis_notes", "")

        # Build vulnerability priorities models if present
        vuln_items = state.get("vuln_priorities", [])
        vuln_models: List[VulnerabilityPriority] = []
        for item in vuln_items:
            try:
                vt = VulnerabilityType(item.get("vuln_type"))
            except Exception:
                # fallback to UNKNOWN mapping if available
                continue
            try:
                pr = Priority(item.get("priority"))
            except Exception:
                pr = Priority.LOW
            reason = item.get("reason", "")
            vuln_models.append(VulnerabilityPriority(vuln_type=vt, priority=pr, reason=reason))

        analysis = ProjectAnalysis(
            language=language,
            framework=framework,
            dependencies=dependencies,
            entry_points=entry_points,
            vulnerability_priorities=vuln_models,
            analysis_notes=analysis_notes,
        )
        state["final_analysis"] = analysis
        state.setdefault("messages", []).append("final_analysis_built")
        return state
    except Exception as exc:
        state["error"] = f"build_final_analysis_node error: {exc}"
        return state


def should_continue(state: AnalyzerState) -> str:
    """Edge function: اگه error داشتیم END، وگرنه ادامه"""
    if state.get("error"):
        return "end"
    return "continue"


# Simple in-file workflow object to avoid a hard dependency on langgraph's
# runtime API while keeping the logical structure explicit.
class _SimpleWorkflow:
    def __init__(self, llm_client: LLMClient):
        self.llm_client = llm_client

    async def execute(self, state: AnalyzerState) -> AnalyzerState:
        # Step 1: scan files
        state = scan_files_node(state)
        if should_continue(state) == "end":
            return state

        # Step 2: analyze with LLM
        state = await analyze_with_llm_node(state, self.llm_client)
        if should_continue(state) == "end":
            return state

        # Step 3: prioritize vulnerabilities
        state = await prioritize_vulnerabilities_node(state, self.llm_client)
        if should_continue(state) == "end":
            return state

        # Step 4: build final analysis
        state = build_final_analysis_node(state)
        return state


# --- ساخت Graph ---
def build_analyzer_graph(llm_client: LLMClient):
    """
    Return a workflow object with an `execute(state)` coroutine.

    The returned object provides a minimal execution API used by `analyze_project`.
    """
    return _SimpleWorkflow(llm_client)


# --- Entry point ---
async def analyze_project(project_path: str, llm_client: LLMClient) -> ProjectAnalysis:
    """
    تابع اصلی که از بیرون فراخوانی میشه

    graph رو اینجوری میسازه، اجرا میکنه، نتیجه رو برمیگردونه
    اگه error داشت AnalyzerError raise کنه
    """
    initial_state: AnalyzerState = {
        "project_path": project_path,
        "scan_result": {},
        "llm_analysis": "",
        "vuln_priorities": [],
        "final_analysis": None,
        "error": None,
        "messages": [],
    }

    workflow = build_analyzer_graph(llm_client)
    state = await workflow.execute(initial_state)

    if state.get("error"):
        raise AnalyzerError(state.get("error"))

    final = state.get("final_analysis")
    if not final:
        raise AnalyzerError("Analyzer did not produce a final analysis")
    return final


class AnalyzerError(Exception):
    pass
