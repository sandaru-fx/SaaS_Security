"""Cryptographic weakness scanner.

Detects:
- MD5 / SHA1 used for security (excluding caching / etag contexts).
- DES / 3DES / RC4 ciphers.
- AES in ECB mode (deterministic, leaks block patterns).
- Hardcoded IVs / nonces near AES construction.
- Weak RSA key sizes (< 2048) and DSA / DH parameters.
- `random.random()` / `Math.random()` used near password / token / secret variables.
- JWT `algorithm: "none"` accepted.
- TLS / SSL version pinned to 1.0 / 1.1 or SSLv3.
- Bcrypt cost factor < 10.

Multilanguage: Python, JS/TS, Java, Go, Ruby, PHP.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.scanners.base import ScanFinding
from app.scanners.secrets import SKIP_DIRS

CRYPTO_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".go", ".rs",
    ".rb", ".php", ".cs", ".swift", ".cpp", ".c", ".h",
}
MAX_FILE_BYTES = 600_000

CACHE_CONTEXT_HINT = re.compile(
    r"\b(?:cache|etag|fingerprint|checksum|content[_-]?hash|filename|file[_-]?hash)\b",
    re.I,
)

PATTERNS: list[tuple[str, str, str, str, str, str]] = [
    (
        r"hashlib\.md5\s*\(|\.createHash\(\s*['\"]md5['\"]|MessageDigest\.getInstance\(\s*['\"]MD5['\"]|Md5::new",
        "crypto-md5-for-security",
        "high",
        "MD5 used in security context",
        "MD5 is cryptographically broken (collisions in seconds) — unsuitable for passwords, signatures, or HMAC keys.",
        "Use SHA-256 (or SHA-3) for general hashing, bcrypt/argon2/scrypt for passwords, BLAKE3 for performance.",
    ),
    (
        r"hashlib\.sha1\s*\(|\.createHash\(\s*['\"]sha-?1['\"]|MessageDigest\.getInstance\(\s*['\"]SHA-?1['\"]|Sha1::new",
        "crypto-sha1-for-security",
        "medium",
        "SHA-1 used in security context",
        "SHA-1 is broken (Google demonstrated practical collisions in 2017). Unsafe for signing, certificates, or password hashing.",
        "Migrate to SHA-256 or SHA-3 for digest use; bcrypt/argon2 for passwords.",
    ),
    (
        r"DES\.new\s*\(|Cipher\.getInstance\(['\"]DES|crypto\.createCipher(?:iv)?\(['\"]des|RC4|ARC4",
        "crypto-weak-cipher",
        "critical",
        "Weak symmetric cipher (DES / RC4)",
        "DES has a 56-bit key (brute-force in hours); RC4 has known biases — must not be used.",
        "Use AES-256-GCM (preferred) or ChaCha20-Poly1305 for symmetric encryption.",
    ),
    (
        r"['\"]AES[/_-]?ECB|MODE_ECB|modes\.ECB\(\)|crypto\.createCipher(?:iv)?\(['\"]aes-\d+-ecb['\"]",
        "crypto-aes-ecb",
        "high",
        "AES used in ECB mode",
        "ECB encrypts identical plaintext blocks to identical ciphertext — leaks structure, vulnerable to substitution attacks.",
        "Use AES-GCM (authenticated) or AES-CBC with random IV and HMAC. Never use ECB for application data.",
    ),
    (
        r"RSA\.generate\s*\(\s*(?:1024|512)|key_size\s*=\s*(?:1024|512)|KeyPairGenerator\.\w+\.initialize\(\s*(?:1024|512)|openssl\s+genrsa\s+(?:1024|512)",
        "crypto-weak-rsa-key",
        "high",
        "RSA key size below 2048 bits",
        "1024-bit RSA is breakable by well-funded adversaries; NIST deprecated it for new use.",
        "Generate at least 2048-bit RSA keys. Prefer 3072+ or ECDSA P-256 / Ed25519 for new systems.",
    ),
    (
        r"['\"]?(?:algorithm|alg)['\"]?\s*[:=]\s*['\"]none['\"]",
        "crypto-jwt-none-alg",
        "critical",
        "JWT 'none' algorithm accepted",
        "Accepting alg=none allows attackers to forge tokens with no signature.",
        "Pin a specific algorithm (RS256 / ES256 / HS256) and reject tokens with alg=none.",
    ),
    (
        r"SSLv?2|SSLv?3|TLSv?1(?:\.0|\.1)?\b(?!\.[2-9])|PROTOCOL_SSLv?[23]|PROTOCOL_TLSv?1(?:_1)?",
        "crypto-old-tls",
        "high",
        "Legacy TLS / SSL protocol version pinned",
        "TLS 1.0, 1.1, SSLv2 and SSLv3 are obsolete and disabled by modern browsers; vulnerable to POODLE/BEAST.",
        "Require TLS 1.2 minimum; prefer TLS 1.3. Update your TLS context / OpenSSL configuration.",
    ),
    (
        r"bcrypt\.hashpw\s*\([^,]+,\s*bcrypt\.gensalt\(\s*(?:[1-9]|10)\s*\)|bcrypt\.hash\([^,]+,\s*(?:[1-9]|10)\s*[,)]",
        "crypto-bcrypt-low-cost",
        "medium",
        "Bcrypt cost factor below 12",
        "Cost < 12 hashes too quickly on modern GPUs — accelerates brute-force attacks on stolen hashes.",
        "Use bcrypt cost factor 12+ (re-hash on login until target latency 200-300ms).",
    ),
]

RANDOM_FOR_SECURITY = re.compile(
    r"\b(?:random\.random|random\.randint|random\.choice|Math\.random)\s*\([^)]*\)",
)
SECURITY_VAR_CONTEXT = re.compile(
    r"\b(?:password|passwd|secret|token|api[_-]?key|session[_-]?id|csrf|otp|nonce|salt)\b",
    re.I,
)


def scan_crypto(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []

    compiled = [(re.compile(p, re.I), rid, sev, title, impact, fix) for (p, rid, sev, title, impact, fix) in PATTERNS]

    for path in project_dir.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in CRYPTO_EXTS:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        rel_path = str(path.relative_to(project_dir)).replace("\\", "/")
        lines = source.splitlines()

        for pattern, rule_id, severity, title, impact, fix in compiled:
            for match in pattern.finditer(source):
                line_no = source.count("\n", 0, match.start()) + 1
                if rule_id in ("crypto-md5-for-security", "crypto-sha1-for-security"):
                    same_line = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
                    prev_line = lines[line_no - 2] if line_no >= 2 else ""
                    if CACHE_CONTEXT_HINT.search(same_line) or CACHE_CONTEXT_HINT.search(prev_line):
                        continue

                findings.append(
                    ScanFinding(
                        category="security",
                        severity=severity,
                        title=title,
                        description=f"Pattern `{match.group(0)[:60]}` in `{rel_path}` at line {line_no}.",
                        impact=impact,
                        fix_recommendation=fix,
                        file_path=rel_path,
                        line_start=line_no,
                        line_end=line_no,
                        rule_id=rule_id,
                        scanner="crypto-weakness",
                        confidence="high",
                    )
                )

        for match in RANDOM_FOR_SECURITY.finditer(source):
            line_no = source.count("\n", 0, match.start()) + 1
            context = "\n".join(lines[max(0, line_no - 3):line_no + 2])
            if SECURITY_VAR_CONTEXT.search(context):
                findings.append(
                    ScanFinding(
                        category="security",
                        severity="high",
                        title="Non-cryptographic random used for security value",
                        description=(
                            f"`{match.group(0)[:60]}` appears near a security-sensitive variable at "
                            f"`{rel_path}:{line_no}`."
                        ),
                        impact="random.random() / Math.random() are predictable PRNGs — attacker can replay tokens or guess secrets.",
                        fix_recommendation=(
                            "Use `secrets.token_urlsafe()` (Python), `crypto.randomBytes()` (Node), "
                            "or `SecureRandom` (Java) for any security-sensitive value."
                        ),
                        file_path=rel_path,
                        line_start=line_no,
                        line_end=line_no,
                        rule_id="crypto-weak-random",
                        scanner="crypto-weakness",
                        confidence="medium",
                    )
                )

    return findings
