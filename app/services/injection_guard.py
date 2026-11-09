import base64
import codecs
import re
import unicodedata
from dataclasses import dataclass
from typing import List, Tuple
from urllib.parse import unquote


@dataclass
class InjectionSignal:
    name: str
    score: float
    evidence: str


def _truncate(evidence: str, max_len: int = 100) -> str:
    evidence = evidence.replace("\n", " ").strip()
    if len(evidence) <= max_len:
        return evidence
    return evidence[:max_len] + "..."


# High-confidence phrases. One hit is enough to block at the default threshold.
# Patterns are matched against a normalized copy of the text, so obfuscation
# that survives normalization (leet, spacing, homoglyphs) still hits them.
_HIGH = [
    (re.compile(r"ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)\s+(?:system\s+)?(?:instructions|prompts|directions|directives|rules)"), "instruction override"),
    (re.compile(r"disregard\s+(?:all\s+|any\s+|your\s+)?(?:previous\s+|prior\s+|safety\s+|security\s+)?(?:guidelines|rules|instructions|policies|restrictions)"), "safety bypass"),
    (re.compile(r"forget\s+(?:all\s+|your\s+)*(?:previous\s+|prior\s+)?(?:instructions|rules|guidelines|training)"), "instruction override"),
    (re.compile(r"do\s+anything\s+now"), "DAN jailbreak"),
    (re.compile(r"\bdan\s+mode\b|\byou\s+are\s+(?:now\s+)?dan\b|\benter\s+dan\b"), "DAN jailbreak"),
    (re.compile(r"reveal\s+(?:your|the)\s+(?:hidden\s+|initial\s+|original\s+|full\s+)?(?:system\s+)?(?:prompt|instructions)"), "prompt extraction"),
    (re.compile(r"(?:show|print|repeat|output|leak|exfiltrate)\s+(?:me\s+)?(?:your|the)\s+(?:hidden\s+|initial\s+|original\s+|full\s+)?(?:system\s+)?(?:prompt|instructions)"), "prompt extraction"),
    (re.compile(r"\[inst\]|\[/inst\]|<\|im_start\|>|<\|im_end\|>|<\|system\|>"), "chat-template injection"),
    (re.compile(r"new\s+(?:system\s+)?instructions?\s*:"), "instruction override"),
    (re.compile(r"override\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions|rules)"), "instruction override"),
    (re.compile(r"(?:answer|respond|reply)\s+as\s+an?\s+(?:unfiltered|unrestricted|jailbroken)"), "role reassignment"),
    (re.compile(r"ignore(?:z|r)?\s+(?:toutes\s+)?(?:les\s+)?instructions\s+pr[eé]c[eé]dentes"), "instruction override"),
    (re.compile(r"ignora(?:r)?\s+(?:todas\s+)?(?:las\s+)?instrucciones\s+anteriores"), "instruction override"),
    (re.compile(r"ignoriere\s+(?:alle\s+)?vorherigen\s+(?:anweisungen|instruktionen)"), "instruction override"),
    (re.compile(r"ignore\s+(?:todas\s+)?(?:as\s+)?instru[cç][oõ]es\s+anteriores"), "instruction override"),
    (re.compile(r"ignora\s+(?:tutte\s+)?(?:le\s+)?istruzioni\s+precedenti"), "instruction override"),
    (re.compile(r"negeer\s+(?:alle\s+)?vorige\s+instructies"), "instruction override"),
    (re.compile(r"忽略(?:之前|以前|以上|先前)(?:的)?(?:所有)?(?:指令|指示|提示)"), "instruction override"),
    (re.compile(r"以前の指示を無視|これまでの指示を無視"), "instruction override"),
    (re.compile(r"تجاهل\s+التعليمات\s+السابقة"), "instruction override"),
    (re.compile(r"игнорируй(?:те)?\s+(?:все\s+)?предыдущие\s+инструкции"), "instruction override"),
]

# These alone stay under the default 0.75 threshold. They matter when a
# request stacks several weaker signals.
_MEDIUM = [
    (re.compile(r"you\s+are\s+now\s+(?:an?\s+)?(?:unfiltered|jailbroken|unrestricted)"), "role reassignment", 0.7),
    (re.compile(r"pretend\s+(?:you\s+are|to\s+be)\s+(?:an?\s+)?(?:evil|unfiltered|unrestricted)"), "roleplay injection", 0.7),
    (re.compile(r"without\s+(?:any\s+)?(?:safety\s+filters|censorship)"), "safety bypass", 0.65),
]

_INVISIBLE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\ufff9-\ufffb]")
_BASE64 = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
_HEX_ESCAPES = re.compile(r"(?:\\x[0-9a-fA-F]{2}){6,}")

# Cyrillic, Greek, and fullwidth letters that are commonly swapped for Latin.
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ї": "i", "ё": "e", "ѕ": "s", "һ": "h", "ј": "j",
    "α": "a", "ο": "o", "ρ": "p", "τ": "t", "ν": "v",
})
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def _collapse_spaced_letters(text: str) -> str:
    def repl(match: re.Match) -> str:
        return re.sub(r"[\s._\-*]+", "", match.group(0))

    return re.sub(
        r"(?<![a-z0-9])(?:[a-z0-9][\s._\-*]){3,}[a-z0-9](?![a-z0-9])",
        repl,
        text,
    )


def _normalize(text: str, fold_homoglyphs: bool) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE.sub("", text)
    text = text.lower()
    if fold_homoglyphs:
        text = text.translate(_HOMOGLYPHS)
    text = _collapse_spaced_letters(text)
    text = text.translate(_LEET)
    text = re.sub(r"\s+", " ", text)
    return text


def _phrases(text: str) -> List[InjectionSignal]:
    signals: List[InjectionSignal] = []
    for pattern, name in _HIGH:
        match = pattern.search(text)
        if match:
            signals.append(InjectionSignal(name, 0.9, _truncate(match.group())))
    for pattern, name, score in _MEDIUM:
        match = pattern.search(text)
        if match:
            signals.append(InjectionSignal(name, score, _truncate(match.group())))
    return signals


def _check_invisible(text: str) -> List[InjectionSignal]:
    matches = _INVISIBLE.findall(text)
    if len(matches) >= 3:
        return [InjectionSignal(
            "invisible_chars",
            min(0.3 + len(matches) * 0.05, 0.8),
            f"{len(matches)} zero-width/RTL chars detected",
        )]
    return []


def _check_homoglyph_count(text: str) -> List[InjectionSignal]:
    folded = text.lower().translate(_HOMOGLYPHS)
    count = sum(1 for a, b in zip(text.lower(), folded) if a != b)
    if count >= 5:
        return [InjectionSignal("homoglyph_evasion", 0.6, f"{count} suspicious homoglyph characters")]
    return []


def _decoded_views(text: str) -> List[Tuple[str, str]]:
    views: List[Tuple[str, str]] = []
    stripped = _INVISIBLE.sub("", text)
    for match in _BASE64.finditer(stripped):
        try:
            decoded = base64.b64decode(match.group(), validate=False).decode("utf-8", errors="ignore")
        except Exception:
            continue
        if decoded and any(ch.isalpha() for ch in decoded):
            views.append(("base64", decoded))
    rot = codecs.decode(text, "rot13")
    if rot != text:
        views.append(("rot13", rot))
    if "%" in text:
        decoded_url = unquote(text)
        if decoded_url != text:
            views.append(("url", decoded_url))
    if _HEX_ESCAPES.search(text):
        def _hex_repl(match: re.Match) -> str:
            raw = match.group(0).replace("\\x", "")
            try:
                return bytes.fromhex(raw).decode("utf-8", errors="ignore")
            except ValueError:
                return match.group(0)
        views.append(("hex", _HEX_ESCAPES.sub(_hex_repl, text)))
    return views


def _dedupe(signals: List[InjectionSignal]) -> List[InjectionSignal]:
    seen = set()
    out = []
    for signal in signals:
        key = (signal.name, signal.evidence)
        if key in seen:
            continue
        seen.add(key)
        out.append(signal)
    return out


def evaluate_injection_risk(text: str, threshold: float = 0.75) -> Tuple[bool, List[InjectionSignal], float]:
    if not text:
        return False, [], 0.0

    signals: List[InjectionSignal] = []
    # Fold homoglyphs in a second pass. Doing it first would turn Cyrillic
    # words into Latin and the multilingual phrases would stop matching.
    plain = _normalize(text, fold_homoglyphs=False)
    folded = _normalize(text, fold_homoglyphs=True)
    signals.extend(_phrases(plain))
    if folded != plain:
        signals.extend(_phrases(folded))
    signals.extend(_check_invisible(text))
    signals.extend(_check_homoglyph_count(text))

    for kind, decoded in _decoded_views(text):
        decoded_norm = _normalize(decoded, fold_homoglyphs=True)
        if decoded_norm == plain or decoded_norm == folded:
            continue
        for signal in _phrases(decoded_norm):
            if signal.score < 0.85:
                continue
            signals.append(InjectionSignal(
                f"{kind}_encoded_{signal.name}",
                round(signal.score * 0.95, 3),
                _truncate(f"{kind} payload decodes to: {decoded[:80]}"),
            ))
            break

    signals = _dedupe(signals)
    if not signals:
        return False, [], 0.0

    combined = 1.0
    for signal in signals:
        combined *= (1.0 - signal.score)
    total = 1.0 - combined
    return total >= threshold, signals, total
