import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class PIIFinding:
    detector: str
    start: int
    end: int
    original: str
    masked: str


_PATTERNS = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    # Contiguous 13-19 digits, or the usual printed groups. A loose "digits and
    # spaces" pattern also swallows phone numbers that happen to sit next to
    # each other, so those shapes are not accepted here.
    "CREDIT_CARD": re.compile(
        r"(?<!\d)(?:"
        r"\d{13,19}"
        r"|\d{4}(?:[ -]\d{4}){2,4}"
        r"|\d{4}[ -]\d{6}[ -]\d{5}"
        r")(?!\d)"
    ),
    "IBAN": re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}\s?[A-Z0-9]{1,4}\b", re.IGNORECASE),
    "PHONE": re.compile(
        r"(?<!\w)(?:"
        r"\+\d{1,3}(?:[\s.-]?\d){8,14}"
        r"|\(\d{3}\)[\s.-]?\d{3}[\s.-]\d{4}"
        r"|\d{3}[\s.-]\d{3}[\s.-]\d{4}"
        r")(?!\w)"
    ),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "NINO": re.compile(r"\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b", re.IGNORECASE),
    "ES_DNI": re.compile(r"\b\d{8}[A-Z]\b", re.IGNORECASE),
    "IP_V4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
    "AWS_ACCESS_KEY": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GENERIC_API_KEY": re.compile(
        r"\b(?:api[_-]?key|apikey|token|secret|password|auth)\s*[:=]\s*['\"]?([A-Za-z0-9_\-./+=]{24,})['\"]?",
        re.IGNORECASE,
    ),
}

_DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"
_NINO_BAD_PREFIX = {"BG", "GB", "KN", "NK", "NT", "TN", "ZZ"}


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


def _iin_ok(number: str) -> bool:
    if number.startswith("4"):
        return True
    if len(number) >= 2 and number[:2] in {str(i) for i in range(51, 56)}:
        return True
    if len(number) >= 4 and number[:4].isdigit() and 2221 <= int(number[:4]) <= 2720:
        return True
    if number[:2] in {"34", "37"}:
        return True
    if number.startswith("6011") or number.startswith("65"):
        return True
    if len(number) >= 3 and number[:3].isdigit() and 300 <= int(number[:3]) <= 305:
        return True
    if number[:2] in {"36", "38"}:
        return True
    if len(number) >= 3 and number[:3].isdigit() and 644 <= int(number[:3]) <= 649:
        return True
    if len(number) >= 4 and number[:4].isdigit() and 3528 <= int(number[:4]) <= 3589:
        return True
    return False


def _is_credit_card(candidate: str) -> bool:
    cleaned = re.sub(r"[ -]", "", candidate)
    if not re.fullmatch(r"\d{13,19}", cleaned):
        return False
    if not _iin_ok(cleaned):
        return False
    return _luhn_check(cleaned)


def _iban_ok(candidate: str) -> bool:
    compact = re.sub(r"\s+", "", candidate).upper()
    if not 15 <= len(compact) <= 34:
        return False
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    digits = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(digits) % 97 == 1


def _ssn_ok(candidate: str) -> bool:
    area, group, serial = candidate.split("-")
    if area in {"000", "666"} or area[0] == "9":
        return False
    if group == "00" or serial == "0000":
        return False
    return True


def _nino_ok(candidate: str) -> bool:
    compact = re.sub(r"\s+", "", candidate).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{6}[A-D]", compact):
        return False
    return compact[:2] not in _NINO_BAD_PREFIX


def _dni_ok(candidate: str) -> bool:
    compact = candidate.upper()
    if not re.fullmatch(r"\d{8}[A-Z]", compact):
        return False
    return _DNI_LETTERS[int(compact[:8]) % 23] == compact[-1]


def _phone_ok(candidate: str) -> bool:
    digits = re.sub(r"\D", "", candidate)
    if not 10 <= len(digits) <= 15:
        return False
    # A run of digits with no + and no separator is a card or an order number.
    if candidate[0] != "+" and not re.search(r"[\s().-]", candidate):
        return False
    return True


def detect_pii(text: str) -> List[PIIFinding]:
    findings: List[PIIFinding] = []
    seen_spans: set[tuple[int, int]] = set()

    def overlaps(start: int, end: int) -> bool:
        return any(not (end <= s or start >= e) for s, e in seen_spans)

    def add(detector: str, start: int, end: int, original: str, masked: str) -> None:
        if overlaps(start, end):
            return
        findings.append(PIIFinding(detector, start, end, original, masked))
        seen_spans.add((start, end))

    for m in _PATTERNS["EMAIL"].finditer(text):
        add("EMAIL", m.start(), m.end(), m.group(), "[EMAIL_REDACTED]")

    for m in _PATTERNS["CREDIT_CARD"].finditer(text):
        if _is_credit_card(m.group()):
            add("CREDIT_CARD", m.start(), m.end(), m.group(), "[CARD_REDACTED]")

    for m in _PATTERNS["IBAN"].finditer(text):
        if _iban_ok(m.group()):
            add("IBAN", m.start(), m.end(), m.group(), "[IBAN_REDACTED]")

    for m in _PATTERNS["SSN"].finditer(text):
        if _ssn_ok(m.group()):
            add("SSN", m.start(), m.end(), m.group(), "[SSN_REDACTED]")

    for m in _PATTERNS["NINO"].finditer(text):
        if _nino_ok(m.group()):
            add("NINO", m.start(), m.end(), m.group(), "[NINO_REDACTED]")

    for m in _PATTERNS["ES_DNI"].finditer(text):
        if _dni_ok(m.group()):
            add("ES_DNI", m.start(), m.end(), m.group(), "[DNI_REDACTED]")

    for m in _PATTERNS["PHONE"].finditer(text):
        if _phone_ok(m.group()):
            add("PHONE", m.start(), m.end(), m.group(), "[PHONE_REDACTED]")

    for m in _PATTERNS["AWS_ACCESS_KEY"].finditer(text):
        add("AWS_KEY", m.start(), m.end(), m.group(), "[AWS_KEY_REDACTED]")

    for m in _PATTERNS["GENERIC_API_KEY"].finditer(text):
        secret = m.group(1)
        if secret.lower() in ("your_api_key", "changeme", "xxx", "placeholder"):
            continue
        add("API_KEY", m.start(1), m.end(1), secret, "[KEY_REDACTED]")

    for m in _PATTERNS["IP_V4"].finditer(text):
        add("IP_ADDRESS", m.start(), m.end(), m.group(), "[IP_REDACTED]")

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


def mask_payload_text(text: Optional[str]) -> Optional[str]:
    if not text:
        return text
    return mask_text(text, detect_pii(text))
