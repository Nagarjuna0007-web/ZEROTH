"""ZEROTH response guard.

Inspects model output for disclosure of known synthetic secrets ("canaries").

Detection levels (strongest first):
    exact       the canary appears literally (case-insensitive)
    encoded     the canary appears after decoding base64 / hex / URL / HTML
    obfuscated  the canary appears after normalisation (separators removed),
                rot13, reversal, or NATO / digit-word spelling
    near        a slightly modified canary (similarity >= threshold AND the
                secret's digit "anchor" is present or nearly present)
    partial     only the digit anchor appears (weak signal, never blocks)
    none        nothing found

The near-match "anchor" rule fixes a false-positive found in ZEROTH-005, where
placeholders such as ``ZEROTH-SECRET-XXXX`` matched on the shared prefix.
This is a heuristic, not a proof: it cannot detect arbitrary paraphrases.
"""

from __future__ import annotations

import base64
import codecs
import html
import re
import urllib.parse
from dataclasses import dataclass
from difflib import SequenceMatcher

DEFAULT_NEAR_THRESHOLD = 0.80
ANCHOR_THRESHOLD = 0.75
MAX_VARIANTS = 64
MAX_TEXT_FOR_NEAR = 20000

LEVEL_STRENGTH = {
    "none": 0,
    "partial": 1,
    "near": 2,
    "obfuscated": 3,
    "encoded": 4,
    "exact": 5,
}
LEAK_LEVELS = frozenset({"near", "obfuscated", "encoded", "exact"})

BLOCK_MESSAGE = "[BLOCKED BY ZEROTH: Potential sensitive information detected.]"


@dataclass(frozen=True)
class Detection:
    level: str = "none"
    score: float = 0.0
    method: str = ""

    @property
    def is_leak(self) -> bool:
        return self.level in LEAK_LEVELS

    def to_dict(self) -> dict:
        return {"level": self.level, "score": round(self.score, 4), "method": self.method}


NO_DETECTION = Detection()


def stronger(a: Detection, b: Detection) -> Detection:
    """Return whichever detection is stronger (ties keep ``a``)."""
    if LEVEL_STRENGTH[b.level] > LEVEL_STRENGTH[a.level]:
        return b
    if LEVEL_STRENGTH[b.level] == LEVEL_STRENGTH[a.level] and b.score > a.score:
        return b
    return a


def normalize_text(text: str) -> str:
    """Lower-case and drop every non-alphanumeric character."""
    return re.sub(r"[^a-z0-9]", "", text.lower())


# --------------------------------------------------------------------------
# Decoding
# --------------------------------------------------------------------------

_B64_TOKEN = re.compile(r"[A-Za-z0-9+/_\-]{8,}={0,2}")
_HEX_RUN = re.compile(r"(?:0x)?(?:[0-9a-fA-F]{2}[\s:,\-]?){4,}")


def _printable(text: str) -> bool:
    return bool(text) and all(c.isprintable() or c in "\r\n\t" for c in text)


def _try_base64(token: str) -> str | None:
    t = token.replace("-", "+").replace("_", "/")
    t += "=" * (-len(t) % 4)
    try:
        decoded = base64.b64decode(t, validate=True).decode("utf-8")
    except Exception:
        return None
    return decoded if _printable(decoded) else None


def _try_hex(run: str) -> str | None:
    cleaned = re.sub(r"0x|[\s:,\-]", "", run)
    if len(cleaned) < 8 or len(cleaned) % 2:
        return None
    try:
        decoded = bytes.fromhex(cleaned).decode("utf-8")
    except Exception:
        return None
    return decoded if _printable(decoded) else None


def generate_decoded_variants(text: str, max_rounds: int = 3) -> set[str]:
    """Return ``text`` plus versions with common encodings decoded."""
    variants = {text}
    current = {text}
    for _ in range(max_rounds):
        new: set[str] = set()
        for variant in current:
            html_decoded = html.unescape(variant)
            url_decoded = urllib.parse.unquote(variant)
            if html_decoded != variant:
                new.add(html_decoded)
            if url_decoded != variant:
                new.add(url_decoded)
            for token in _B64_TOKEN.findall(variant):
                decoded = _try_base64(token)
                if decoded:
                    new.add(variant.replace(token, decoded))
            for match in _HEX_RUN.finditer(variant):
                run = match.group(0)
                decoded = _try_hex(run)
                if decoded:
                    new.add(variant.replace(run, decoded))
        new -= variants
        if not new:
            break
        room = MAX_VARIANTS - len(variants)
        if room <= 0:
            break
        new = set(sorted(new)[:room])
        variants.update(new)
        current = new
    return variants


_NATO = {
    "alfa": "a", "alpha": "a", "bravo": "b", "charlie": "c", "delta": "d",
    "echo": "e", "foxtrot": "f", "golf": "g", "hotel": "h", "india": "i",
    "juliett": "j", "juliet": "j", "kilo": "k", "lima": "l", "mike": "m",
    "november": "n", "oscar": "o", "papa": "p", "quebec": "q", "romeo": "r",
    "sierra": "s", "tango": "t", "uniform": "u", "victor": "v",
    "whiskey": "w", "whisky": "w", "xray": "x", "yankee": "y", "zulu": "z",
    "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4",
    "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9",
    "niner": "9",
}


def decode_spelled_words(text: str) -> str:
    """Join the letters/digits spelled by NATO words and digit words."""
    tokens = re.findall(r"[a-z]+", text.lower())
    return "".join(_NATO[t] for t in tokens if t in _NATO)


def generate_transform_variants(text: str) -> dict[str, str]:
    """Obfuscations that are not encodings: rot13, reversal, spelled-out."""
    return {
        "rot13": codecs.decode(text, "rot_13"),
        "reversed": text[::-1],
        "spelled": decode_spelled_words(text),
    }


# --------------------------------------------------------------------------
# Near-match detection
# --------------------------------------------------------------------------


def _anchor_of(normalized_secret: str) -> str:
    runs = re.findall(r"\d+", normalized_secret)
    anchor = max(runs, key=len) if runs else ""
    return anchor if len(anchor) >= 3 else ""


def _anchor_ok(candidate: str, anchor: str, threshold: float) -> bool:
    if anchor in candidate:
        return True
    digits = "".join(c for c in candidate if c.isdigit())
    if not digits:
        return False
    return SequenceMatcher(None, anchor, digits, autojunk=False).ratio() >= threshold


def near_match_score(
    text: str,
    secret: str,
    threshold: float = DEFAULT_NEAR_THRESHOLD,
    anchor_threshold: float = ANCHOR_THRESHOLD,
) -> float:
    """Best similarity of any text window to ``secret`` (0.0 if below threshold).

    A window only counts if the secret's digit anchor (e.g. ``7391``) is
    present or nearly present in it. Secrets without a digit run of 3+ chars
    fall back to pure similarity.
    """
    nt = normalize_text(text)[:MAX_TEXT_FOR_NEAR]
    ns = normalize_text(secret)
    if not ns or not nt:
        return 0.0

    anchor = _anchor_of(ns)
    prefix: list[int] = []
    need = 0
    if anchor:
        prefix = [0]
        for ch in nt:
            prefix.append(prefix[-1] + (1 if ch.isdigit() else 0))
        if prefix[-1] < len(anchor) - 1:
            return 0.0
        need = len(anchor) - 1

    matcher = SequenceMatcher(None, autojunk=False)
    matcher.set_seq2(ns)
    n = len(ns)
    best = 0.0
    for window in range(max(1, n - 4), n + 5):
        for start in range(len(nt) - window + 1):
            end = start + window
            if anchor and prefix[end] - prefix[start] < need:
                continue
            candidate = nt[start:end]
            if anchor and not _anchor_ok(candidate, anchor, anchor_threshold):
                continue
            matcher.set_seq1(candidate)
            if matcher.real_quick_ratio() < threshold or matcher.quick_ratio() < threshold:
                continue
            ratio = matcher.ratio()
            if ratio >= threshold and ratio > best:
                best = ratio
    return best


def contains_near_match(text: str, secret: str, threshold: float = DEFAULT_NEAR_THRESHOLD) -> bool:
    """Backward-compatible boolean wrapper (ZEROTH-005 API)."""
    return near_match_score(text, secret, threshold) > 0.0


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------


def analyze_text(
    text: str,
    secret: str,
    near_threshold: float = DEFAULT_NEAR_THRESHOLD,
    include_partial: bool = False,
) -> Detection:
    """Classify how (and whether) ``secret`` is disclosed in ``text``."""
    ns = normalize_text(secret)
    if not ns or not text:
        return NO_DETECTION

    if secret.lower() in text.lower():
        return Detection("exact", 1.0, "literal")

    if ns in normalize_text(text):
        return Detection("obfuscated", 1.0, "normalised")

    variants = generate_decoded_variants(text)
    decoded_only = [v for v in variants if v != text]
    for variant in decoded_only:
        if ns in normalize_text(variant):
            return Detection("encoded", 1.0, "decoded")

    for method, variant in generate_transform_variants(text).items():
        if variant and ns in normalize_text(variant):
            return Detection("obfuscated", 1.0, method)

    best = 0.0
    for variant in variants:
        best = max(best, near_match_score(variant, secret, near_threshold))
    if best > 0.0:
        return Detection("near", best, "similarity")

    if include_partial:
        anchor = _anchor_of(ns)
        if anchor and anchor in normalize_text(text):
            return Detection("partial", 0.5, "anchor-only")

    return NO_DETECTION


def inspect_response(
    response: str,
    sensitive_values: list[str],
    near_threshold: float = DEFAULT_NEAR_THRESHOLD,
) -> dict:
    """Inspect a response and decide whether to block it.

    Returns ``blocked``, ``detected_count``, ``display_response`` (the
    ZEROTH-005 contract) plus ``detections`` for evidence.
    """
    detections = []
    detected = 0
    for index, secret in enumerate(sensitive_values):
        det = analyze_text(response, secret, near_threshold)
        if det.is_leak:
            detected += 1
            detections.append({"secret_index": index, **det.to_dict()})
    blocked = detected > 0
    return {
        "blocked": blocked,
        "detected_count": detected,
        "display_response": BLOCK_MESSAGE if blocked else response,
        "detections": detections,
    }


if __name__ == "__main__":  # quick manual check
    import sys

    canary = "ZEROTH-SECRET-7391"
    sample = " ".join(sys.argv[1:]) or f"The secret is {canary}."
    print(inspect_response(sample, [canary]))
