import re
from dataclasses import dataclass
from typing import List


@dataclass
class PIIFinding:
    detector: str
    start: int
    end: int
    original: str
    masked: str


_PATTERNS = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "PHONE": re.compile(r"(?<!\d)(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{3,4}(?!\d)"),
    "CREDIT_CARD": re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "IP_V4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
    "AWS_ACCESS_KEY": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GENERIC_API_KEY": re.compile(
        r"\b(?:api[_-]?key|apikey|token|secret|password|auth)\s*[:=]\s*['\"]?([A-Za-z0-9_\-./+=]{24,})['\"]?",
        re.IGNORECASE,
    ),
}


def _luhn_check(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    for i, d in enumerate(digits[::-1]):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _is_credit_card(candidate: str) -> bool:
    cleaned = candidate.replace(" ", "").replace("-", "")
    if not cleaned.isdigit():
        return False
    if not re.match(r"^(4|5[1-5]|3[47]|6(?:011|5))", cleaned):
        return False
    return _luhn_check(cleaned)


def detect_pii(text: str) -> List[PIIFinding]:
    findings: List[PIIFinding] = []
    seen_spans = set()

    def overlaps(start: int, end: int) -> bool:
        return any(not (end <= s or start >= e) for s, e in seen_spans)

    for m in _PATTERNS["EMAIL"].finditer(text):
        if not overlaps(m.start(), m.end()):
            findings.append(PIIFinding("EMAIL", m.start(), m.end(), m.group(), "[EMAIL_REDACTED]"))
            seen_spans.add((m.start(), m.end()))

    for m in _PATTERNS["CREDIT_CARD"].finditer(text):
        if _is_credit_card(m.group()) and not overlaps(m.start(), m.end()):
            findings.append(PIIFinding("CREDIT_CARD", m.start(), m.end(), m.group(), "[CARD_REDACTED]"))
            seen_spans.add((m.start(), m.end()))

    for m in _PATTERNS["SSN"].finditer(text):
        if not overlaps(m.start(), m.end()):
            findings.append(PIIFinding("SSN", m.start(), m.end(), m.group(), "[SSN_REDACTED]"))
            seen_spans.add((m.start(), m.end()))

    for m in _PATTERNS["AWS_ACCESS_KEY"].finditer(text):
        if not overlaps(m.start(), m.end()):
            findings.append(PIIFinding("AWS_KEY", m.start(), m.end(), m.group(), "[AWS_KEY_REDACTED]"))
            seen_spans.add((m.start(), m.end()))

    for m in _PATTERNS["GENERIC_API_KEY"].finditer(text):
        secret = m.group(1)
        if secret.lower() in ("your_api_key", "changeme", "xxx", "placeholder"):
            continue
        if not overlaps(m.start(1), m.end(1)):
            findings.append(PIIFinding("API_KEY", m.start(1), m.end(1), secret, "[KEY_REDACTED]"))
            seen_spans.add((m.start(1), m.end(1)))

    for m in _PATTERNS["IP_V4"].finditer(text):
        if not overlaps(m.start(), m.end()):
            findings.append(PIIFinding("IP_ADDRESS", m.start(), m.end(), m.group(), "[IP_REDACTED]"))
            seen_spans.add((m.start(), m.end()))

    findings.sort(key=lambda f: f.start)
    return findings


def mask_text(text: str, findings: List[PIIFinding]) -> str:
    if not findings:
        return text
    result = text
    for f in reversed(findings):
        result = result[:f.start] + f.masked + result[f.end:]
    return result


def summarize_findings(findings: List[PIIFinding]) -> dict:
    counts: dict = {}
    for f in findings:
        counts[f.detector] = counts.get(f.detector, 0) + 1
    return counts
