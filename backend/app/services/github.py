import re
from urllib.parse import urlparse

GITHUB_URL_PATTERN = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)


def parse_github_url(url: str) -> tuple[str, str]:
    """Return (owner, repo) from a GitHub repository URL."""
    cleaned = url.strip().rstrip("/")
    match = GITHUB_URL_PATTERN.match(cleaned)
    if not match:
        raise ValueError("Invalid GitHub URL. Use format: https://github.com/owner/repo")
    owner, repo = match.group(1), match.group(2)
    if repo.endswith(".git"):
        repo = repo[:-4]
    return owner, repo


def build_github_zipball_url(owner: str, repo: str, branch: str) -> str:
    return f"https://api.github.com/repos/{owner}/{repo}/zipball/{branch}"
