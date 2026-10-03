#!/usr/bin/env python3
"""Fail if any tracked text file contains a download-and-execute pattern.

Checks README.md, scripts, workflows and sources for `curl|bash`, `wget|sh`,
`bash <(curl ...)`, `sh -c "$(curl ...)"`, `eval $(curl ...)`, and (for Python)
shell=True / os.system. Also fails if install.sh reappears.
Usage: python3 tests/check_no_pipe_to_shell.py   (exit 1 on findings)
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SELF = os.path.relpath(os.path.abspath(__file__), ROOT)

FETCH = r"(?:curl|wget|fetch|iwr|Invoke-WebRequest)"
SHELL = r"(?:ba|z|da|k)?sh|python3?|perl|ruby|node"
PATTERNS = [
    ("pipe from downloader to shell", re.compile(rf"\b{FETCH}\b[^\n|]*\|\s*(?:sudo\s+)?(?:{SHELL})\b")),
    ("process substitution of downloader", re.compile(rf"(?:ba|z)?sh\s+<\(\s*{FETCH}\b|source\s+<\(\s*{FETCH}\b")),
    ("command substitution of downloader", re.compile(rf"(?:eval|(?:ba)?sh\s+-c)\s+[\"']?\$\(\s*{FETCH}\b")),
]
PY_PATTERNS = [
    ("subprocess shell=True", re.compile(r"shell\s*=\s*True")),
    ("os.system", re.compile(r"\bos\.system\s*\(")),
]


def tracked_files():
    out = subprocess.run(["git", "-C", ROOT, "ls-files"], capture_output=True, text=True)
    if out.returncode == 0 and out.stdout.strip():
        return out.stdout.splitlines()
    return [os.path.relpath(os.path.join(d, f), ROOT) for d, _, fs in os.walk(ROOT)
            if ".git" not in d.split(os.sep) for f in fs]


def main():
    problems = []
    if os.path.exists(os.path.join(ROOT, "install.sh")):
        problems.append("install.sh must not exist (use `omarchy plugin add`)")
    for rel in tracked_files():
        if rel == SELF or not rel:
            continue
        path = os.path.join(ROOT, rel)
        if not os.path.isfile(path) or rel.endswith((".png", ".jpg", ".svg")):
            continue
        try:
            text = open(path, encoding="utf-8").read()
        except (UnicodeDecodeError, OSError):
            continue
        is_py = rel.endswith(".py") or text.startswith("#!/usr/bin/env python")
        pats = PATTERNS + (PY_PATTERNS if is_py else [])
        for n, line in enumerate(text.splitlines(), 1):
            for label, rx in pats:
                if rx.search(line):
                    problems.append(f"{rel}:{n}: {label}: {line.strip()[:100]}")
    if problems:
        print("FAIL: unsafe install/exec patterns found:")
        print("\n".join(problems))
        return 1
    print("ok: no pipe-to-shell or remote-exec patterns found")
    return 0


if __name__ == "__main__":
    sys.exit(main())
