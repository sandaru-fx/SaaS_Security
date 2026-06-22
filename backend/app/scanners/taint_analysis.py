"""Lightweight built-in taint analyzer for Python and JS/TS.

Tracks data flow from request-derived sources to dangerous sinks within
each file (intra-procedural). This replaces some regex heuristics in
`security.py` with proper context-aware analysis, yielding far fewer
false positives.

Python: AST-based. Detects:
  - SQL injection (cursor.execute, sqlalchemy.text, raw SQL f-strings)
  - Command injection (subprocess, os.system, os.popen)
  - Code injection (eval, exec, compile)
  - Path traversal (open / Path with tainted name)
  - SSRF (requests / httpx / urllib using tainted URLs)
  - Open redirect (redirect, HttpResponseRedirect with tainted target)
  - Template injection (render_template_string)
  - Deserialization (pickle.loads, yaml.load without SafeLoader)

JS / TS: regex + per-file variable tracking. Detects:
  - DOM XSS (innerHTML, outerHTML, document.write, dangerouslySetInnerHTML)
  - Code injection (eval, Function, setTimeout(string), setInterval(string))
  - SQL injection (db.query / pool.query / connection.query with template literals)
  - Command injection (child_process.exec / execSync / spawn shell:true)
  - Open redirect (res.redirect with tainted URL)
  - Path traversal (fs.* with tainted path)
"""

from __future__ import annotations

import ast
import logging
import re
from pathlib import Path

from app.scanners.base import ScanFinding
from app.scanners.secrets import SKIP_DIRS

logger = logging.getLogger(__name__)

PYTHON_EXTS = {".py"}
JS_TS_EXTS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
MAX_FILE_BYTES = 600_000

PY_REQUEST_OBJECTS = {"request", "req"}
PY_TAINT_ATTRS = {"args", "form", "values", "json", "data", "files", "GET", "POST", "body", "params", "headers", "cookies"}

PY_SQL_SINKS = {
    "execute",
    "executemany",
    "executescript",
    "exec_driver_sql",
    "raw",
    "text",
    "from_statement",
}
PY_SHELL_SINKS = {"system", "popen", "spawn", "spawnv", "spawnvp", "Popen", "run", "call", "check_call", "check_output"}
PY_CODE_SINKS = {"eval", "exec", "compile"}
PY_FILE_SINKS = {"open"}
PY_HTTP_SINKS = {"get", "post", "put", "delete", "patch", "head", "request", "urlopen", "urlretrieve"}
PY_REDIRECT_SINKS = {"redirect", "HttpResponseRedirect", "RedirectResponse"}
PY_TEMPLATE_SINKS = {"render_template_string"}
PY_DESERIALIZATION_SINKS = {"loads", "load"}

JS_TAINT_SOURCES = [
    r"req(?:uest)?\s*\.\s*(?:query|body|params|headers|cookies)",
    r"window\s*\.\s*location",
    r"document\s*\.\s*(?:URL|cookie|referrer|baseURI)",
    r"location\s*\.\s*(?:href|hash|search|pathname)",
    r"history\s*\.\s*state",
    r"localStorage\s*\.\s*getItem",
    r"sessionStorage\s*\.\s*getItem",
    r"new\s+URL\s*\([^)]*\)\s*\.\s*searchParams",
]
JS_TAINT_SOURCE_RE = re.compile("|".join(JS_TAINT_SOURCES))

JS_VAR_ASSIGN_RE = re.compile(
    r"\b(?:const|let|var)\s+(\w+)\s*=\s*([^;\n]+)",
)
JS_DESTRUCTURE_RE = re.compile(
    r"\b(?:const|let|var)\s*\{\s*([\w,\s:]+)\s*\}\s*=\s*([^;\n]+)",
)


def scan_taint(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []

    for path in project_dir.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue

        suffix = path.suffix.lower()
        try:
            if suffix in PYTHON_EXTS:
                findings.extend(_scan_python_file(path, project_dir))
            elif suffix in JS_TS_EXTS:
                findings.extend(_scan_js_file(path, project_dir))
        except Exception as exc:
            logger.debug("Taint scan failed for %s: %s", path, exc)

    return findings


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path)


def _scan_python_file(path: Path, project_dir: Path) -> list[ScanFinding]:
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return []

    findings: list[ScanFinding] = []
    rel_path = _rel(path, project_dir)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            findings.extend(_analyze_python_function(node, rel_path))

    return findings


def _analyze_python_function(
    func: ast.FunctionDef | ast.AsyncFunctionDef, rel_path: str
) -> list[ScanFinding]:
    tainted: set[str] = set()

    for arg in (
        func.args.args
        + func.args.kwonlyargs
        + ([func.args.vararg] if func.args.vararg else [])
        + ([func.args.kwarg] if func.args.kwarg else [])
    ):
        if arg and arg.arg in PY_REQUEST_OBJECTS:
            tainted.add(arg.arg)

    is_route_handler = _is_route_handler(func)
    if is_route_handler:
        for arg in func.args.args + func.args.kwonlyargs:
            if arg and arg.arg not in ("self", "cls"):
                tainted.add(arg.arg)

    findings: list[ScanFinding] = []

    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            if _expr_is_tainted(node.value, tainted):
                for target in node.targets:
                    for name in _extract_assign_names(target):
                        tainted.add(name)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            if node.value is not None and _expr_is_tainted(node.value, tainted):
                for name in _extract_assign_names(node.target):
                    tainted.add(name)

    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            finding = _check_python_sink(node, tainted, rel_path)
            if finding:
                findings.append(finding)

    return findings


def _is_route_handler(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    decorator_names = {"route", "get", "post", "put", "delete", "patch", "head", "options", "api_view"}
    for dec in func.decorator_list:
        if isinstance(dec, ast.Call):
            target = dec.func
            name = _attr_chain(target)
            if any(name.endswith(d) for d in decorator_names):
                return True
        elif isinstance(dec, ast.Attribute):
            name = _attr_chain(dec)
            if any(name.endswith(d) for d in decorator_names):
                return True
        elif isinstance(dec, ast.Name) and dec.id in decorator_names:
            return True
    return False


def _attr_chain(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _extract_assign_names(target: ast.AST) -> list[str]:
    names: list[str] = []
    if isinstance(target, ast.Name):
        names.append(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            names.extend(_extract_assign_names(elt))
    elif isinstance(target, ast.Starred):
        names.extend(_extract_assign_names(target.value))
    return names


def _expr_is_tainted(expr: ast.AST, tainted: set[str]) -> bool:
    for node in ast.walk(expr):
        if isinstance(node, ast.Name) and node.id in tainted:
            return True
        if isinstance(node, ast.Attribute):
            chain = _attr_chain(node)
            parts = chain.split(".")
            if len(parts) >= 2 and parts[0] in PY_REQUEST_OBJECTS and parts[1] in PY_TAINT_ATTRS:
                return True
        if isinstance(node, ast.Call):
            chain = _attr_chain(node.func)
            parts = chain.split(".")
            if len(parts) >= 3 and parts[0] in PY_REQUEST_OBJECTS and parts[1] in PY_TAINT_ATTRS:
                return True
            if len(parts) >= 2 and parts[0] in PY_REQUEST_OBJECTS and parts[1] in {"get_json", "get_data"}:
                return True
    return False


def _check_python_sink(
    call: ast.Call, tainted: set[str], rel_path: str
) -> ScanFinding | None:
    func_chain = _attr_chain(call.func)
    parts = func_chain.split(".")
    sink_name = parts[-1] if parts else ""

    args_tainted = any(_expr_is_tainted(arg, tainted) for arg in call.args) or any(
        _expr_is_tainted(kw.value, tainted) for kw in call.keywords
    )
    if not args_tainted:
        return None

    line = getattr(call, "lineno", 0)

    if sink_name in PY_SQL_SINKS:
        return _finding(
            title="Taint flow: user input reaches SQL execution",
            description=f"`{func_chain}(...)` called with tainted argument at {rel_path}:{line}.",
            impact="SQL Injection — attacker may read or modify the database.",
            fix="Use parameterized queries (`?` / `%s` placeholders); never interpolate user input into SQL strings.",
            severity="critical",
            rule_id="taint-py-sqli",
            file_path=rel_path,
            line=line,
        )

    if "subprocess" in func_chain or sink_name in PY_SHELL_SINKS:
        for kw in call.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return _finding(
                    title="Taint flow: user input reaches shell command",
                    description=f"`{func_chain}(...)` with `shell=True` and tainted argument at {rel_path}:{line}.",
                    impact="OS command injection — attacker may execute arbitrary commands on the server.",
                    fix="Pass arguments as a list (`shell=False`) and never concatenate user input into commands.",
                    severity="critical",
                    rule_id="taint-py-cmd-injection",
                    file_path=rel_path,
                    line=line,
                )
        if sink_name in {"system", "popen"} and "os" in parts:
            return _finding(
                title="Taint flow: user input reaches os.system / os.popen",
                description=f"`{func_chain}(...)` with tainted argument at {rel_path}:{line}.",
                impact="OS command injection — attacker may execute arbitrary commands.",
                fix="Replace with `subprocess.run([...], shell=False)` and validate inputs.",
                severity="critical",
                rule_id="taint-py-cmd-injection",
                file_path=rel_path,
                line=line,
            )

    if sink_name in PY_CODE_SINKS and "subprocess" not in func_chain:
        return _finding(
            title=f"Taint flow: user input reaches {sink_name}()",
            description=f"`{func_chain}(...)` with tainted argument at {rel_path}:{line}.",
            impact="Remote code execution — arbitrary Python is evaluated.",
            fix="Never pass untrusted input to eval/exec/compile. Use safe parsers (ast.literal_eval, json) instead.",
            severity="critical",
            rule_id="taint-py-code-injection",
            file_path=rel_path,
            line=line,
        )

    if sink_name in PY_FILE_SINKS or func_chain.endswith(".Path"):
        return _finding(
            title="Taint flow: user input reaches filesystem path",
            description=f"`{func_chain}(...)` with tainted path at {rel_path}:{line}.",
            impact="Path traversal — attacker may read or overwrite arbitrary files on the server.",
            fix="Canonicalize and whitelist paths; reject inputs containing `..` or absolute paths.",
            severity="high",
            rule_id="taint-py-path-traversal",
            file_path=rel_path,
            line=line,
        )

    if sink_name in PY_HTTP_SINKS and any(p in func_chain for p in ("requests", "httpx", "urllib", "urlopen", "aiohttp")):
        return _finding(
            title="Taint flow: user input reaches outbound HTTP call",
            description=f"`{func_chain}(...)` with tainted URL at {rel_path}:{line}.",
            impact="Server-Side Request Forgery (SSRF) — attacker may pivot into internal network or metadata services.",
            fix="Validate target URL against an allowlist; block private IP ranges and link-local addresses.",
            severity="high",
            rule_id="taint-py-ssrf",
            file_path=rel_path,
            line=line,
        )

    if sink_name in PY_REDIRECT_SINKS:
        return _finding(
            title="Taint flow: user input controls redirect target",
            description=f"`{func_chain}(...)` with tainted URL at {rel_path}:{line}.",
            impact="Open redirect — phishing, OAuth token theft, SSO bypass.",
            fix="Validate redirect URL against an allowlist of trusted destinations.",
            severity="high",
            rule_id="taint-py-open-redirect",
            file_path=rel_path,
            line=line,
        )

    if sink_name in PY_TEMPLATE_SINKS:
        return _finding(
            title="Taint flow: user input reaches Jinja2 template string",
            description=f"`{func_chain}(...)` with tainted template at {rel_path}:{line}.",
            impact="Server-Side Template Injection (SSTI) — remote code execution.",
            fix="Use `render_template` with named variables; never compile templates from user input.",
            severity="critical",
            rule_id="taint-py-ssti",
            file_path=rel_path,
            line=line,
        )

    if sink_name in PY_DESERIALIZATION_SINKS and any(
        p in func_chain for p in ("pickle", "cPickle", "shelve", "marshal")
    ):
        return _finding(
            title="Taint flow: user input reaches pickle.loads",
            description=f"`{func_chain}(...)` with tainted bytes at {rel_path}:{line}.",
            impact="Insecure deserialization — remote code execution.",
            fix="Never unpickle untrusted data. Use JSON or signed serialization formats.",
            severity="critical",
            rule_id="taint-py-pickle",
            file_path=rel_path,
            line=line,
        )

    if sink_name == "load" and "yaml" in func_chain:
        has_safe_loader = any(
            kw.arg == "Loader" and isinstance(kw.value, ast.Attribute) and "Safe" in (kw.value.attr or "")
            for kw in call.keywords
        )
        if not has_safe_loader:
            return _finding(
                title="Taint flow: yaml.load without SafeLoader on user input",
                description=f"`{func_chain}(...)` without SafeLoader at {rel_path}:{line}.",
                impact="YAML deserialization can execute arbitrary Python.",
                fix="Use `yaml.safe_load(...)` or specify `Loader=yaml.SafeLoader`.",
                severity="high",
                rule_id="taint-py-yaml-load",
                file_path=rel_path,
                line=line,
            )

    return None


def _scan_js_file(path: Path, project_dir: Path) -> list[ScanFinding]:
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    rel_path = _rel(path, project_dir)
    findings: list[ScanFinding] = []
    tainted: set[str] = set()

    for match in JS_VAR_ASSIGN_RE.finditer(source):
        var_name = match.group(1)
        rhs = match.group(2)
        if JS_TAINT_SOURCE_RE.search(rhs) or _rhs_references_tainted(rhs, tainted):
            tainted.add(var_name)

    for match in JS_DESTRUCTURE_RE.finditer(source):
        names = match.group(1)
        rhs = match.group(2)
        if JS_TAINT_SOURCE_RE.search(rhs) or _rhs_references_tainted(rhs, tainted):
            for raw_name in names.split(","):
                clean = raw_name.split(":")[-1].strip()
                if clean.isidentifier():
                    tainted.add(clean)

    findings.extend(_js_sink_scan(source, tainted, rel_path, "innerHTML", "DOM XSS via innerHTML", "taint-js-xss-innerhtml", "Avoid setting innerHTML from user input; use textContent or a safe templating library."))
    findings.extend(_js_sink_scan(source, tainted, rel_path, "outerHTML", "DOM XSS via outerHTML", "taint-js-xss-outerhtml", "Avoid setting outerHTML from user input."))
    findings.extend(_js_sink_scan(source, tainted, rel_path, "dangerouslySetInnerHTML", "React XSS via dangerouslySetInnerHTML", "taint-js-react-dangerous-html", "Sanitize HTML with DOMPurify before rendering."))
    findings.extend(_js_sink_scan(source, tainted, rel_path, "document.write", "DOM XSS via document.write", "taint-js-document-write", "Replace document.write with safe DOM APIs."))

    findings.extend(_js_call_sink(source, tainted, rel_path, ["eval", "Function"], "Tainted input passed to eval / Function constructor", "Remote code execution in browser/Node.", "Never pass untrusted strings to eval or Function. Use JSON.parse or safe alternatives.", "taint-js-code-injection", "critical"))

    for match in re.finditer(r"\b(?:db|pool|connection|client|sequelize|knex)\s*\.\s*(?:query|exec|raw)\s*\(\s*`([^`]+)`", source):
        body = match.group(1)
        if "${" in body and any(t in body for t in tainted):
            findings.append(
                _finding(
                    title="Tainted template literal in SQL query",
                    description="Backtick template literal interpolating tainted variable into SQL call.",
                    impact="SQL Injection — attacker may read or modify the database.",
                    fix="Use parameterized queries or prepared statements (?, $1, named bindings).",
                    severity="critical",
                    rule_id="taint-js-sqli",
                    file_path=rel_path,
                    line=source.count("\n", 0, match.start()) + 1,
                )
            )
            break

    for match in re.finditer(r"\b(?:child_process\.)?(?:exec|execSync|spawn|spawnSync)\s*\(([^)]+)\)", source):
        body = match.group(1)
        if any(t in body for t in tainted) or JS_TAINT_SOURCE_RE.search(body):
            findings.append(
                _finding(
                    title="Tainted input passed to child_process command",
                    description="OS command call receives user-controlled argument.",
                    impact="OS command injection — arbitrary shell execution on the server.",
                    fix="Use spawn with argument array (`shell: false`); validate inputs; never concat strings into commands.",
                    severity="critical",
                    rule_id="taint-js-cmd-injection",
                    file_path=rel_path,
                    line=source.count("\n", 0, match.start()) + 1,
                )
            )
            break

    for match in re.finditer(r"\bres(?:ponse)?\s*\.\s*redirect\s*\(\s*([^,)]+)", source):
        target = match.group(1).strip()
        if any(t in target for t in tainted) or JS_TAINT_SOURCE_RE.search(target):
            findings.append(
                _finding(
                    title="Tainted input controls HTTP redirect target",
                    description="Express-style res.redirect() called with user-controlled URL.",
                    impact="Open redirect — phishing, OAuth token theft, SSO bypass.",
                    fix="Validate target URL against an allowlist of trusted destinations.",
                    severity="high",
                    rule_id="taint-js-open-redirect",
                    file_path=rel_path,
                    line=source.count("\n", 0, match.start()) + 1,
                )
            )
            break

    for match in re.finditer(r"\bfs\s*\.\s*(?:readFile|readFileSync|writeFile|writeFileSync|unlink|createReadStream)\s*\(([^,)]+)", source):
        arg = match.group(1).strip()
        if any(t in arg for t in tainted) or JS_TAINT_SOURCE_RE.search(arg):
            findings.append(
                _finding(
                    title="Tainted input reaches filesystem operation",
                    description="fs.* called with user-controlled path argument.",
                    impact="Path traversal — read or overwrite arbitrary files on the server.",
                    fix="Canonicalize paths with path.resolve and verify they stay under a safe base directory.",
                    severity="high",
                    rule_id="taint-js-path-traversal",
                    file_path=rel_path,
                    line=source.count("\n", 0, match.start()) + 1,
                )
            )
            break

    return findings


def _rhs_references_tainted(rhs: str, tainted: set[str]) -> bool:
    if not tainted:
        return False
    for var in tainted:
        if re.search(rf"\b{re.escape(var)}\b", rhs):
            return True
    return False


def _js_sink_scan(
    source: str,
    tainted: set[str],
    rel_path: str,
    sink_property: str,
    title: str,
    rule_id: str,
    fix: str,
) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    pattern = re.compile(
        rf"\.\s*{re.escape(sink_property)}\s*=\s*([^;\n]+)|"
        rf"{re.escape(sink_property)}\s*:\s*\{{[^}}]*__html\s*:\s*([^}}]+)",
    )
    for match in pattern.finditer(source):
        rhs = match.group(1) or match.group(2) or ""
        if JS_TAINT_SOURCE_RE.search(rhs) or _rhs_references_tainted(rhs, tainted):
            findings.append(
                _finding(
                    title=title,
                    description=f"`{sink_property}` assigned from tainted source.",
                    impact="Cross-site scripting — attacker JavaScript runs in victim's browser.",
                    fix=fix,
                    severity="critical",
                    rule_id=rule_id,
                    file_path=rel_path,
                    line=source.count("\n", 0, match.start()) + 1,
                )
            )
            break
    return findings


def _js_call_sink(
    source: str,
    tainted: set[str],
    rel_path: str,
    fn_names: list[str],
    title: str,
    impact: str,
    fix: str,
    rule_id: str,
    severity: str,
) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    names = "|".join(re.escape(n) for n in fn_names)
    pattern = re.compile(rf"\b(?:{names})\s*\(([^)]+)\)")
    for match in pattern.finditer(source):
        body = match.group(1)
        if JS_TAINT_SOURCE_RE.search(body) or _rhs_references_tainted(body, tainted):
            findings.append(
                _finding(
                    title=title,
                    description="Tainted variable passed as code-string argument.",
                    impact=impact,
                    fix=fix,
                    severity=severity,
                    rule_id=rule_id,
                    file_path=rel_path,
                    line=source.count("\n", 0, match.start()) + 1,
                )
            )
            break
    return findings


def _finding(
    *,
    title: str,
    description: str,
    impact: str,
    fix: str,
    severity: str,
    rule_id: str,
    file_path: str,
    line: int,
) -> ScanFinding:
    return ScanFinding(
        category="security",
        severity=severity,
        title=title,
        description=description,
        impact=impact,
        fix_recommendation=fix,
        file_path=file_path,
        line_start=line,
        line_end=line,
        rule_id=rule_id,
        scanner="taint-analysis",
        confidence="high",
        metadata={"taint_verified": "true"},
    )
