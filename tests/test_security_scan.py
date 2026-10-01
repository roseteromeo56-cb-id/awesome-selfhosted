import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN_PATTERNS = {
    "MediaWiki exported user token": re.compile(
        r'\b(?:csrfToken|watchToken|patrolToken)"\s*:\s*"(?!REDACTED_TOKEN")[^"]+',
        re.IGNORECASE,
    ),
    "MediaWiki user token export block": re.compile(
        r"\bmw\.user\.tokens\.set\s*\(",
        re.IGNORECASE,
    ),
    "Authenticated MediaWiki username": re.compile(
        r'"wgUserName"\s*:\s*"(?!REDACTED_USER")',
        re.IGNORECASE,
    ),
    "Authenticated MediaWiki numeric user id": re.compile(
        r'"wgUserId"\s*:\s*\d+',
        re.IGNORECASE,
    ),
    "MediaWiki user registration metadata": re.compile(
        r'"wgNoticeUserData"\s*:',
        re.IGNORECASE,
    ),
    "Browser extension script URL": re.compile(
        r"\b(?:chrome|moz)-extension://",
        re.IGNORECASE,
    ),
    "Injected wallet extension marker": re.compile(
        r"\bdata-bybit-(?:channel-name|is-default-wallet)\b",
        re.IGNORECASE,
    ),
}

TEXT_SUFFIXES = {
    "",
    ".css",
    ".html",
    ".js",
    ".json",
    ".md",
    ".php",
    ".svg",
    ".txt",
    ".xml",
    ".yml",
    ".yaml",
}


def iter_text_files():
    for path in ROOT.rglob("*"):
        if path.is_dir() or ".git" in path.parts:
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        yield path


def scan_for_forbidden_artifacts():
    findings = []
    for path in iter_text_files():
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as error:
            findings.append((path, "Unreadable file", str(error)))
            continue

        for name, pattern in FORBIDDEN_PATTERNS.items():
            for match in pattern.finditer(content):
                line = content.count("\n", 0, match.start()) + 1
                findings.append((path, name, line))
    return findings


class SecurityScanTest(unittest.TestCase):
    def test_no_exported_browser_session_artifacts(self):
        findings = scan_for_forbidden_artifacts()
        formatted = "\n".join(
            f"{path.relative_to(ROOT)}:{line}: {name}"
            for path, name, line in findings[:20]
        )
        self.assertEqual([], findings, formatted)


if __name__ == "__main__":
    unittest.main()
