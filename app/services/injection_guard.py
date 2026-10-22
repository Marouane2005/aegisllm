import base64
import re
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class InjectionSignal:
    name: str
    score: float
    evidence: str


def _truncate(evidence: str, max_len: int = 100) -> str:
    if len(evidence) <= max_len:
        return evidence
    return evidence[:max_len] + "..."


_JAILBREAK_PATTERNS: List[Tuple[re.Pattern, float, str]] = [
    (re.compile(r"\bDAN\b|\bdo\s+anything\s+now\b", re.I), 0.9, "DAN jailbreak"),
    (re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I), 0.85, "instruction override"),
    (re.compile(r"you\s+are\s+now\s+(?:a|an)\s+", re.I), 0.7, "role reassignment"),
    (re.compile(r"pretend\s+you\s+are", re.I), 0.7, "roleplay injection"),
    (re.compile(r"act\s+as\s+(?:if\s+)?(?:a|an|if)\s+", re.I), 0.6, "roleplay injection"),
    (re.compile(r"disregard\s+(all\s+)?(safety|guidelines|rules)", re.I), 0.85, "safety bypass"),
    (re.compile(r"system\s*:\s*", re.I), 0.5, "system prompt injection attempt"),
    (re.compile(r"\[INST\]|\[/INST\]|<\|im_start\|>", re.I), 0.8, "chat-template injection"),
    (re.compile(r"reveal\s+your\s+(initial|system|original)\s+instructions", re.I), 0.8, "prompt extraction"),
]

_INVISIBLE_CHARS = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\ufff9-\ufffb]"
)
_BASE64_PATTERN = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")


def _check_jailbreak_phrases(text: str) -> List[InjectionSignal]:
    signals = []
    text_lower = text.lower()
    for pattern, weight, name in _JAILBREAK_PATTERNS:
        m = pattern.search(text_lower)
        if m:
            start = max(0, m.start() - 20)
            end = min(len(text), m.end() + 20)
            evidence = text[start:end].replace("\n", " ").strip()
            signals.append(InjectionSignal(name, weight, _truncate(evidence)))
    return signals


def _check_invisible_chars(text: str) -> List[InjectionSignal]:
    matches = _INVISIBLE_CHARS.findall(text)
    if len(matches) >= 3:
        return [InjectionSignal(
            "invisible_chars",
            min(0.3 + len(matches) * 0.05, 0.8),
            f"{len(matches)} zero-width/RTL chars detected",
        )]
    return []


def _check_encoded_payloads(text: str) -> List[InjectionSignal]:
    signals = []
    for m in _BASE64_PATTERN.finditer(text):
        try:
            decoded = base64.b64decode(m.group()).decode("utf-8", errors="ignore")
            for pattern, weight, name in _JAILBREAK_PATTERNS:
                if pattern.search(decoded.lower()):
                    signals.append(InjectionSignal(
                        f"base64_encoded_{name}",
                        weight * 0.9,
                        _truncate(f"base64 payload decodes to: {decoded[:80]}"),
                    ))
                    break
        except Exception:
            pass
    return signals


def _check_homoglyphs(text: str) -> List[InjectionSignal]:
    homoglyph_map = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i"}
    count = sum(1 for c in text.lower() if c in homoglyph_map)
    if count >= 5:
        return [InjectionSignal("homoglyph_evasion", 0.6, f"{count} suspicious homoglyph characters")]
    return []


def evaluate_injection_risk(text: str, threshold: float = 0.75) -> Tuple[bool, List[InjectionSignal], float]:
    all_signals: List[InjectionSignal] = []
    all_signals.extend(_check_jailbreak_phrases(text))
    all_signals.extend(_check_invisible_chars(text))
    all_signals.extend(_check_encoded_payloads(text))
    all_signals.extend(_check_homoglyphs(text))

    if not all_signals:
        return False, [], 0.0

    combined = 1.0
    for s in all_signals:
        combined *= (1.0 - s.score)
    total_score = 1.0 - combined

    return total_score >= threshold, all_signals, total_score
