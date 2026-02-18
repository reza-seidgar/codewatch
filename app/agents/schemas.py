"""Shared data schemas for Agent components"""
from pydantic import BaseModel
from enum import Enum
from typing import Optional, List


class Language(str, Enum):
    CSHARP = "csharp"
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    GO = "go"
    UNKNOWN = "unknown"


class Framework(str, Enum):
    DOTNET = "dotnet"
    DOTNET_WEBAPI = "dotnet_webapi"
    DJANGO = "django"
    FASTAPI = "fastapi"
    FLASK = "flask"
    EXPRESS = "express"
    NESTJS = "nestjs"
    SPRING = "spring"
    UNKNOWN = "unknown"


class VulnerabilityType(str, Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    AUTH_BYPASS = "auth_bypass"
    IDOR = "idor"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    HARDCODED_SECRETS = "hardcoded_secrets"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"


class Priority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class VulnerabilityPriority(BaseModel):
    vuln_type: VulnerabilityType
    priority: Priority
    reason: str  # چرا این اولویت داده شده


class ProjectAnalysis(BaseModel):
    """خروجی نهایی Analyzer Agent"""
    language: Language
    framework: Framework
    dependencies: List[str]           # لیست dependency های اصلی
    entry_points: List[str]           # فایل‌های اصلی پروژه (relative path)
    vulnerability_priorities: List[VulnerabilityPriority]
    analysis_notes: str               # توضیحات کلی درباره پروژه
