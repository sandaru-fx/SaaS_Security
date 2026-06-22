"""AI/LLM security scanner — OWASP LLM Top 10 static analysis.

Detects prompt injection vectors, dangerous LangChain agents/tools,
insecure RAG patterns, missing output validation, and client-side API keys.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from app.scanners.base import ScanFinding
from app.scanners.utils import iter_code_files, read_lines, rel_path, should_skip

LLM_FILE_MARKER = re.compile(
    r"(?i)\b(langchain|openai|anthropic|ChatOpenAI|ChatAnthropic|"
    r"google\.generativeai|google\.genai|litellm|llama_index|llama_index|"
    r"haystack|instructor|guidance|semantic_kernel|autogen|crewai|"
    r"vertexai|boto3\.client\(['\"]bedrock|ollama)\b"
)

USER_INPUT_VARS = r"(?:user(?:_input|_message|_query|_prompt)?|request\.|body\.|input|query|message|prompt_text|chat_message)"


@dataclass(frozen=True)
class LlmRule:
    rule_id: str
    pattern: re.Pattern[str]
    severity: str
    title: str
    description: str
    impact: str
    fix: str
    owasp_llm: str
    requires_llm_context: bool = True
    confidence: str = "medium"


def _rules() -> list[LlmRule]:
    return [
        LlmRule(
            rule_id="llm-prompt-injection-fstring",
            pattern=re.compile(
                rf'(?i)f["\'][^"\']*\{{{USER_INPUT_VARS}',
            ),
            severity="high",
            title="User input interpolated into LLM prompt (f-string)",
            description="User-controlled data is embedded in an f-string prompt template.",
            impact="Attackers can inject instructions to bypass guardrails or exfiltrate secrets (LLM01).",
            fix="Use structured prompts with input sanitization, delimiters, and a separate untrusted user block.",
            owasp_llm="LLM01:2025 - Prompt Injection",
        ),
        LlmRule(
            rule_id="llm-prompt-injection-format",
            pattern=re.compile(
                rf'(?i)\.format\([^)]*{USER_INPUT_VARS}',
            ),
            severity="high",
            title="User input passed to prompt .format()",
            description="String .format() builds LLM prompts from user-controlled variables.",
            impact="Classic prompt injection — attackers can override system instructions.",
            fix="Avoid .format() for prompts; use parameterized templates with validation and length limits.",
            owasp_llm="LLM01:2025 - Prompt Injection",
        ),
        LlmRule(
            rule_id="llm-prompt-concatenation",
            pattern=re.compile(
                rf'(?i)(prompt|system_prompt|instructions)\s*\+?=?\s*.*{USER_INPUT_VARS}',
            ),
            severity="high",
            title="User input concatenated into LLM prompt",
            description="Prompt string is built via concatenation with user-controlled input.",
            impact="Enables direct prompt injection and instruction override.",
            fix="Keep system and user messages separate; never concatenate raw user text into system prompts.",
            owasp_llm="LLM01:2025 - Prompt Injection",
        ),
        LlmRule(
            rule_id="llm-direct-user-passthrough",
            pattern=re.compile(
                r'(?i)(?:HumanMessage|UserMessage|ChatMessage)\s*\(\s*(?:content\s*=\s*)?(?:request\.|user\.|input|body\.)',
            ),
            severity="medium",
            title="Raw HTTP/request body passed as LLM user message",
            description="Request data is passed directly to an LLM message constructor without validation.",
            impact="Unfiltered user content reaches the model — prompt injection risk.",
            fix="Validate, normalize, and truncate user input before constructing LLM messages.",
            owasp_llm="LLM01:2025 - Prompt Injection",
        ),
        LlmRule(
            rule_id="llm-output-to-exec",
            pattern=re.compile(
                r"(?i)(?:eval|exec|subprocess\.(?:run|call|Popen)|os\.system)\s*\([^)]*(?:response|completion|llm_output|model_output|ai_response)",
            ),
            severity="critical",
            title="LLM output executed as code or shell command",
            description="Model-generated text is passed to eval, exec, or subprocess.",
            impact="Successful prompt injection can lead to remote code execution (LLM02 + LLM08).",
            fix="Never execute LLM output. Use strict allow-listed tools with human approval.",
            owasp_llm="LLM02:2025 - Insecure Output Handling",
            confidence="high",
        ),
        LlmRule(
            rule_id="llm-output-innerhtml",
            pattern=re.compile(
                r"(?i)(?:innerHTML|dangerouslySetInnerHTML)\s*=\s*.*(?:response|completion|llm|ai_message|bot_reply)",
            ),
            severity="high",
            title="LLM output rendered as HTML without sanitization",
            description="AI-generated content is injected into the DOM unsafely.",
            impact="Model can return XSS payloads — insecure output handling.",
            fix="Sanitize LLM output (DOMPurify) or render as plain text only.",
            owasp_llm="LLM02:2025 - Insecure Output Handling",
        ),
        LlmRule(
            rule_id="llm-langchain-python-repl",
            pattern=re.compile(r"\b(?:PythonREPLTool|PythonAstREPLTool)\b"),
            severity="critical",
            title="LangChain Python REPL tool enabled",
            description="PythonREPLTool allows the model to execute arbitrary Python code.",
            impact="Prompt injection can achieve full code execution in the app environment.",
            fix="Remove REPL tools; use narrow, sandboxed function calling with explicit allow lists.",
            owasp_llm="LLM08:2025 - Excessive Agency",
            confidence="high",
        ),
        LlmRule(
            rule_id="llm-langchain-shell-tool",
            pattern=re.compile(
                r"\b(?:ShellTool|BashProcess|Terminal|ShellCommandTool|execute_command)\b"
            ),
            severity="critical",
            title="LangChain shell/terminal tool enabled",
            description="Agent has access to shell or terminal execution tools.",
            impact="Model or injected prompts can run arbitrary OS commands.",
            fix="Disable shell tools; require human-in-the-loop for any system interaction.",
            owasp_llm="LLM08:2025 - Excessive Agency",
            confidence="high",
        ),
        LlmRule(
            rule_id="llm-langchain-sql-agent",
            pattern=re.compile(
                r"\b(?:create_sql_agent|SQLDatabaseChain|SQLDatabaseToolkit|QuerySQLDataBaseTool)\b"
            ),
            severity="high",
            title="LangChain SQL agent without implied sandbox",
            description="SQL agent lets the LLM generate and run database queries.",
            impact="Prompt injection can exfiltrate or destroy database contents.",
            fix="Use read-only DB roles, query allow lists, and row-level security.",
            owasp_llm="LLM08:2025 - Excessive Agency",
        ),
        LlmRule(
            rule_id="llm-langchain-dangerous-code",
            pattern=re.compile(r"allow_dangerous_code\s*=\s*True"),
            severity="critical",
            title="LangChain allow_dangerous_code=True",
            description="Dangerous code execution is explicitly enabled in LangChain.",
            impact="Bypasses safety guardrails for code-running agents.",
            fix="Set allow_dangerous_code=False and use sandboxed tool execution.",
            owasp_llm="LLM08:2025 - Excessive Agency",
            confidence="high",
        ),
        LlmRule(
            rule_id="llm-langchain-verbose-leak",
            pattern=re.compile(r"(?i)\bverbose\s*=\s*True"),
            severity="medium",
            title="LangChain verbose mode may leak prompts",
            description="verbose=True logs intermediate chains including prompts and tool I/O.",
            impact="Sensitive prompts, PII, or secrets may appear in application logs.",
            fix="Disable verbose in production; use structured audit logging with redaction.",
            owasp_llm="LLM06:2025 - Sensitive Information Disclosure",
        ),
        LlmRule(
            rule_id="llm-rag-url-loader",
            pattern=re.compile(
                r"\b(?:WebBaseLoader|RecursiveUrlLoader|UnstructuredURLLoader|SitemapLoader)\b"
            ),
            severity="medium",
            title="RAG loads documents from arbitrary URLs",
            description="URL-based document loaders can fetch untrusted web content into the vector store.",
            impact="Training-time / retrieval poisoning — attacker-controlled content influences answers.",
            fix="Allow-list domains, sanitize fetched content, and detect injection in retrieved chunks.",
            owasp_llm="LLM03:2025 - Training Data Poisoning",
        ),
        LlmRule(
            rule_id="llm-rag-no-chunk-auth",
            pattern=re.compile(
                r"(?i)(?:similarity_search|as_retriever|vectorstore\.search)\([^)]*\)(?!.*(?:filter|where|metadata))"
            ),
            severity="medium",
            title="Vector retrieval without metadata filter",
            description="Similarity search may return chunks from other tenants or sensitive collections.",
            impact="Cross-tenant data leakage via RAG retrieval.",
            fix="Always filter vector queries by tenant/user metadata and enforce ACLs on chunks.",
            owasp_llm="LLM06:2025 - Sensitive Information Disclosure",
            confidence="low",
        ),
        LlmRule(
            rule_id="llm-missing-max-tokens",
            pattern=re.compile(
                r"(?i)(?:chat\.completions\.create|messages\.create|generate_content)\([^)]*\)"
            ),
            severity="low",
            title="LLM API call may omit max_tokens limit",
            description="LLM invocation on this line does not obviously set max_tokens / max_output_tokens.",
            impact="Unbounded completions increase cost and enable denial-of-wallet / DoS (LLM04).",
            fix="Set max_tokens, timeout, and per-user rate limits on all LLM calls.",
            owasp_llm="LLM04:2025 - Data and Model Denial of Service",
            confidence="low",
        ),
        LlmRule(
            rule_id="llm-client-side-openai",
            pattern=re.compile(
                r"(?i)(?:new\s+OpenAI\s*\(|from\s+['\"]openai['\"]|OpenAI\s*\(\s*\{[^}]*apiKey)"
            ),
            severity="critical",
            title="OpenAI client initialized in frontend code",
            description="OpenAI SDK or API key usage detected in client-side JavaScript/TypeScript.",
            impact="API keys exposed to browsers — credential theft and bill fraud.",
            fix="Proxy LLM calls through your backend; never ship API keys to clients.",
            owasp_llm="LLM06:2025 - Sensitive Information Disclosure",
            requires_llm_context=False,
            confidence="high",
        ),
        LlmRule(
            rule_id="llm-system-prompt-client",
            pattern=re.compile(
                r'(?i)(?:const|let|var)\s+SYSTEM_PROMPT\s*=\s*["\']'
            ),
            severity="medium",
            title="System prompt hardcoded in client-side code",
            description="SYSTEM_PROMPT constant in frontend exposes instructions to users.",
            impact="Attackers can study and bypass guardrails; IP leakage of prompt engineering.",
            fix="Keep system prompts server-side only; client sends user messages to your API.",
            owasp_llm="LLM07:2025 - System Prompt Leakage",
            requires_llm_context=False,
        ),
        LlmRule(
            rule_id="llm-chat-route-no-rate-limit",
            pattern=re.compile(
                r'(?i)@(?:app|router)\.(?:post|get)\(["\'][^"\']*(?:chat|completion|ask|generate)[^"\']*["\']'
            ),
            severity="medium",
            title="LLM chat HTTP endpoint without visible rate limiting",
            description="Chat/completion route defined — no rate limit decorator detected in file.",
            impact="Unauthenticated LLM endpoints enable abuse and cost exhaustion.",
            fix="Add rate limiting, authentication, and per-user quotas on AI endpoints.",
            owasp_llm="LLM04:2025 - Data and Model Denial of Service",
            requires_llm_context=False,
            confidence="low",
        ),
        LlmRule(
            rule_id="llm-auto-tool-approval",
            pattern=re.compile(
                r"(?i)(?:auto_approve|human_in_the_loop\s*=\s*False|require_human_approval\s*=\s*False)"
            ),
            severity="high",
            title="Agent tools auto-approved without human review",
            description="Tool calls are automatically approved without human-in-the-loop.",
            impact="Prompt injection can trigger destructive tool actions without confirmation.",
            fix="Require explicit human approval for sensitive tools and high-impact actions.",
            owasp_llm="LLM08:2025 - Excessive Agency",
        ),
        LlmRule(
            rule_id="llm-pickle-serialization",
            pattern=re.compile(
                r"(?i)(?:pickle\.loads?|dill\.loads?)\([^)]*(?:embedding|vector|memory|cache)"
            ),
            severity="high",
            title="Unsafe deserialization of LLM memory/embeddings cache",
            description="pickle/dill used for LLM memory or embedding caches.",
            impact="Arbitrary code execution if cache files are attacker-controlled.",
            fix="Use JSON or msgpack for caches; sign and encrypt persisted agent memory.",
            owasp_llm="LLM03:2025 - Training Data Poisoning",
        ),
        LlmRule(
            rule_id="llm-crewai-code-execution",
            pattern=re.compile(r"(?i)\b(?:CodeInterpreterTool|code_execution)\b"),
            severity="critical",
            title="Agent framework code execution tool",
            description="CrewAI or similar code interpreter tool detected.",
            impact="Autonomous agents can run arbitrary code from model output.",
            fix="Sandbox code execution or remove interpreter tools from production agents.",
            owasp_llm="LLM08:2025 - Excessive Agency",
            confidence="high",
        ),
        LlmRule(
            rule_id="llm-instructor-unchecked",
            pattern=re.compile(
                r"(?i)instructor\.(?:patch|from_openai|from_anthropic)"
            ),
            severity="low",
            title="Structured LLM output via instructor — validate schemas",
            description="instructor library used for structured outputs.",
            impact="Without server-side schema validation, malformed outputs may bypass business logic.",
            fix="Validate parsed objects server-side; never trust model JSON for security decisions.",
            owasp_llm="LLM02:2025 - Insecure Output Handling",
            confidence="low",
        ),
    ]


def scan_llm_security(project_dir: Path) -> list[ScanFinding]:
    rules = _rules()
    findings: list[ScanFinding] = []
    seen: set[tuple[str, str, int]] = set()

    llm_files: set[str] = set()
    for path in iter_code_files(project_dir):
        if should_skip(path):
            continue
        content = "\n".join(read_lines(path) or [])
        if LLM_FILE_MARKER.search(content):
            llm_files.add(str(path))

    if not llm_files:
        return findings

    for path in iter_code_files(project_dir):
        if should_skip(path):
            continue
        rel = rel_path(path, project_dir)
        lines = read_lines(path) or []
        file_has_llm = str(path) in llm_files
        full_text = "\n".join(lines)

        for rule in rules:
            if rule.requires_llm_context and not file_has_llm:
                continue

            if rule.rule_id == "llm-missing-max-tokens":
                findings.extend(
                    _check_missing_max_tokens(path, rel, lines, rule, seen)
                )
                continue

            if rule.rule_id == "llm-chat-route-no-rate-limit":
                findings.extend(
                    _check_chat_route_rate_limit(path, rel, lines, rule, seen, full_text)
                )
                continue

            for idx, line in enumerate(lines, 1):
                if not rule.pattern.search(line):
                    continue
                key = (rule.rule_id, rel, idx)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(_make_finding(rule, rel, idx, line.strip()[:120]))

    findings.extend(_scan_llm_dependencies(project_dir, llm_files))
    return findings


def _check_missing_max_tokens(
    path: Path,
    rel: str,
    lines: list[str],
    rule: LlmRule,
    seen: set[tuple[str, str, int]],
) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    call_re = re.compile(
        r"(?i)(?:chat\.completions\.create|messages\.create|generate_content)\s*\("
    )
    for idx, line in enumerate(lines, 1):
        if not call_re.search(line):
            continue
        window = " ".join(lines[idx - 1 : min(len(lines), idx + 8)])
        if re.search(r"(?i)max_(?:tokens|output_tokens)|max_tokens\s*=", window):
            continue
        key = (rule.rule_id, rel, idx)
        if key in seen:
            continue
        seen.add(key)
        findings.append(_make_finding(rule, rel, idx, line.strip()[:120]))
    return findings


def _check_chat_route_rate_limit(
    path: Path,
    rel: str,
    lines: list[str],
    rule: LlmRule,
    seen: set[tuple[str, str, int]],
    full_text: str,
) -> list[ScanFinding]:
    if not rule.pattern.search(full_text):
        return []
    if re.search(r"(?i)(?:rate_limit|limiter|throttle|RateLimiter|slowapi)", full_text):
        return []

    findings: list[ScanFinding] = []
    for idx, line in enumerate(lines, 1):
        if not rule.pattern.search(line):
            continue
        key = (rule.rule_id, rel, idx)
        if key in seen:
            continue
        seen.add(key)
        findings.append(_make_finding(rule, rel, idx, line.strip()[:120]))
    return findings


def _scan_llm_dependencies(project_dir: Path, llm_files: set[str]) -> list[ScanFinding]:
    if not llm_files:
        return []

    dep_markers: list[tuple[str, str]] = []
    for pkg_json in project_dir.rglob("package.json"):
        if should_skip(pkg_json) or "node_modules" in pkg_json.parts:
            continue
        try:
            import json

            data = json.loads(pkg_json.read_text(encoding="utf-8"))
        except Exception:
            continue
        deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})}
        for name in deps:
            if re.search(r"(?i)langchain|openai|@anthropic|llamaindex|crewai|autogen", name):
                dep_markers.append((name, rel_path(pkg_json, project_dir)))

    for req in project_dir.rglob("requirements.txt"):
        if should_skip(req):
            continue
        for line in read_lines(req) or []:
            if re.search(r"(?i)^(langchain|openai|anthropic|litellm|llama-index|crewai)", line.strip()):
                dep_markers.append((line.strip().split("=")[0], rel_path(req, project_dir)))

    if not dep_markers:
        return []

    security_hints = False
    for fpath in llm_files:
        text = Path(fpath).read_text(encoding="utf-8", errors="ignore").lower()
        if any(
            hint in text
            for hint in (
                "guardrails",
                "llamaguard",
                "prompt injection",
                "sanitize",
                "max_tokens",
                "human_in_the_loop",
                "content_filter",
            )
        ):
            security_hints = True
            break

    if security_hints:
        return []

    first_dep, first_file = dep_markers[0]
    return [
        ScanFinding(
            category="security",
            severity="low",
            title="LLM dependencies without visible guardrails",
            description=(
                f"Project uses `{first_dep}` but no guardrail patterns "
                "(content filters, sanitization, rate limits) were detected in LLM code."
            ),
            impact="LLM features may ship without baseline OWASP LLM Top 10 controls.",
            fix_recommendation=(
                "Add input validation, output filtering, max_tokens, rate limits, "
                "and human approval for agent tools."
            ),
            file_path=first_file,
            line_start=0,
            line_end=0,
            rule_id="llm-no-guardrails-detected",
            scanner="llm-security",
            confidence="low",
            metadata={"owasp_llm": "LLM09:2025 - Misinformation / Overreliance"},
        )
    ]


def _make_finding(rule: LlmRule, rel: str, line_no: int, snippet: str) -> ScanFinding:
    return ScanFinding(
        category="security",
        severity=rule.severity,
        title=rule.title,
        description=f"{rule.description} Snippet: `{snippet}`",
        impact=rule.impact,
        fix_recommendation=rule.fix,
        file_path=rel,
        line_start=line_no,
        line_end=line_no,
        rule_id=rule.rule_id,
        scanner="llm-security",
        confidence=rule.confidence,
        metadata={"owasp_llm": rule.owasp_llm, "cwe_id": "CWE-1427"},
    )
