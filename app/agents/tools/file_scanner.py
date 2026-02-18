"""Project file scanning utilities used by Analyzer agents.

This module provides a pure-Python scanner that discovers project structure,
collects files by extension, finds configuration/dependency files and reads a
limited amount of their content. It purposely avoids calling any LLMs and is
safe to use as a synchronous tool inside agent workflows.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Any

# فایل‌هایی که نشان‌دهنده زبان/فریمورک هستند
LANGUAGE_INDICATORS = {
    "csharp": [".csproj", ".sln", ".cs"],
    "python": ["requirements.txt", "pyproject.toml", "setup.py", ".py"],
    "javascript": ["package.json", ".js"],
    "typescript": ["tsconfig.json", ".ts"],
    "java": ["pom.xml", "build.gradle", ".java"],
    "go": ["go.mod", ".go"],
}

FRAMEWORK_INDICATORS = {
    "dotnet_webapi": ["Microsoft.AspNetCore", "WebApplication.CreateBuilder"],
    "django": ["django", "DJANGO_SETTINGS_MODULE"],
    "fastapi": ["fastapi", "FastAPI("],
    "flask": ["flask", "Flask(__name__)"] ,
    "express": ["express", "require('express')"],
    "nestjs": ["@nestjs/core", "@nestjs/common"],
    "spring": ["spring-boot", "SpringApplication"],
}

# Directories to skip while walking the tree
_SKIP_DIRS = {"node_modules", ".git", "bin", "obj"}

# Dependency/config filenames to read content for
_DEPENDENCY_FILES = {
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "Pipfile",
    "pom.xml",
    "build.gradle",
    "go.mod",
}


def read_file_safe(file_path: str, max_bytes: int = 10240) -> str:
    """Safely read up to `max_bytes` bytes from a file and return decoded text.

    If the file cannot be read or decoded, return an empty string. Binary files
    will be decoded using utf-8 with replacement for invalid sequences.
    """
    try:
        with open(file_path, "rb") as fh:
            data = fh.read(max_bytes)
        # decode best-effort
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _build_directory_tree(root: Path, max_depth: int = 2) -> str:
    """Return a simple two-level directory tree string for `root`.

    The format is a human-readable indented list. Only directories and files up
    to `max_depth` levels (root depth = 0) are included.
    """
    lines: List[str] = [str(root)]

    if max_depth <= 0:
        return "\n".join(lines)

    try:
        for child in sorted(root.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            if child.name in _SKIP_DIRS:
                continue
            lines.append(f"├─ {child.name}/" if child.is_dir() else f"├─ {child.name}")
            # second level
            if child.is_dir() and max_depth >= 2:
                try:
                    for sub in sorted(child.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
                        if sub.name in _SKIP_DIRS:
                            continue
                        lines.append(f"│  ├─ {sub.name}/" if sub.is_dir() else f"│  ├─ {sub.name}")
                except Exception:
                    continue
    except Exception:
        # If we can't list the directory, return the root only
        return "\n".join(lines)

    return "\n".join(lines)


def _is_dependency_file(name: str) -> bool:
    return name in _DEPENDENCY_FILES


def scan_project_structure(project_path: str) -> Dict[str, Any]:
    """Scan a project directory and return structural information.

    Returned dictionary keys:
    - files_by_extension: mapping ext -> list of relative paths
    - config_files: list of config/dependency filenames found (relative paths)
    - total_files: total number of files scanned (excluding skipped dirs)
    - directory_tree: human-readable tree up to 2 levels deep
    - dependency_files_content: mapping filename -> file content (up to 10KB)

    Notes:
    - Skips directories: node_modules, .git, bin, obj
    - Reads dependency/config files fully up to 10KB
    - directory_tree shows up to 2 levels depth
    """
    root = Path(project_path)
    files_by_extension: Dict[str, List[str]] = {}
    config_files: List[str] = []
    dependency_files_content: Dict[str, str] = {}
    total_files = 0

    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"Project path not found or not a directory: {project_path}")

    # Walk the tree, skipping unwanted directories
    for dirpath, dirnames, filenames in os.walk(root):
        # mutate dirnames in-place to skip large dirs
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]

        for fname in filenames:
            try:
                total_files += 1
                full = Path(dirpath) / fname
                rel = full.relative_to(root)
                # extension-based grouping
                ext = full.suffix.lstrip(".") or "noext"
                files_by_extension.setdefault(ext, []).append(str(rel))

                # config/dependency files detection (by exact name)
                if fname in _DEPENDENCY_FILES:
                    config_files.append(str(rel))
                    # read content (max 10 KB)
                    content = read_file_safe(str(full), max_bytes=10 * 1024)
                    dependency_files_content[str(rel)] = content

            except Exception:
                # Ignore single-file errors and continue
                continue

    # directory tree (2 levels)
    directory_tree = _build_directory_tree(root, max_depth=2)

    result: Dict[str, Any] = {
        "files_by_extension": files_by_extension,
        "config_files": config_files,
        "total_files": total_files,
        "directory_tree": directory_tree,
        "dependency_files_content": dependency_files_content,
    }
    return result
