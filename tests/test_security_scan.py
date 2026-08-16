import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", "tests"}
TEXT_SUFFIXES = {".html", ".js", ".json", ".md", ".php", ".svg", ".txt", ".yml", ".yaml"}

SECURITY_PATTERNS = {
    "MediaWiki session token": re.compile(
        r'"(?:csrf|watch|patrol)Token"\s*:\s*"(?!REDACTED_TOKEN")'
    ),
    "authenticated MediaWiki username": re.compile(
        r'"wgUserName"\s*:\s*"(?!REDACTED_USER")'
    ),
    "authenticated MediaWiki numeric user id": re.compile(r'"wgUserId"\s*:\s*\d+'),
    "MediaWiki user registration metadata": re.compile(r'"wgNoticeUserData"\s*:'),
    "browser extension resource capture": re.compile(r"chrome-extension://"),
    "browser wallet extension metadata": re.compile(r"\bdata-bybit-"),
}


def iter_text_files():
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(REPO_ROOT).parts):
            continue
        if path.suffix in TEXT_SUFFIXES or path.name in {"README", "LICENSE"}:
            yield path


class SecurityScanTest(unittest.TestCase):
    def test_no_captured_session_artifacts(self):
        findings = []
        for path in iter_text_files():
            try:
                content = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                content = path.read_text(encoding="utf-8", errors="ignore")

            for name, pattern in SECURITY_PATTERNS.items():
                for match in pattern.finditer(content):
                    line = content.count("\n", 0, match.start()) + 1
                    findings.append(f"{path.relative_to(REPO_ROOT)}:{line}: {name}")

        self.assertEqual([], findings)


if __name__ == "__main__":
    unittest.main()
