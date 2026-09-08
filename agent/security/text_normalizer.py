from __future__ import annotations

import unicodedata

"""
Detection-only text normalization for evasion resistance.

The output of these functions is used ONLY as an additional signal
fed to guards (InputGuard, SemanticGuard) alongside the original
text -- never returned to the user, never sent to the LLM, never
used for anything user-facing. That distinction matters: it lets
normalize_leetspeak() be reasonably aggressive without risking
corruption of real content (security alert text is full of IPs,
ports, rule IDs, CVE numbers -- exactly what a careless digit-to-
letter pass would mangle).
"""

_ZERO_WIDTH_CHARS = (
    "​"  # zero width space
    "‌"  # zero width non-joiner
    "‍"  # zero width joiner
    "﻿"  # zero width no-break space / BOM
)

# Common lookalike characters used to evade literal-phrase matching.
# Not exhaustive -- covers the characters actually seen in practice
# (Cyrillic/Greek letters that are visually near-identical to Latin
# ones in most fonts).
_HOMOGLYPH_MAP = {
    "а": "a", "А": "A",  # Cyrillic a
    "е": "e", "Е": "E",  # Cyrillic e
    "о": "o", "О": "O",  # Cyrillic o
    "р": "p", "Р": "P",  # Cyrillic er
    "с": "c", "С": "C",  # Cyrillic es
    "і": "i", "І": "I",  # Cyrillic i
    "ѕ": "s", "Ѕ": "S",  # Cyrillic dze
    "у": "y", "У": "Y",  # Cyrillic u
    "х": "x", "Х": "X",  # Cyrillic ha
    "ј": "j", "Ј": "J",  # Cyrillic je
    "ԛ": "q",
    "ѡ": "w",
    "α": "a", "ο": "o", "ρ": "p", "υ": "u", "ν": "v", "κ": "k",  # Greek
}

_LEET_MAP = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    }
)


def strip_zero_width(text: str) -> str:
    for char in _ZERO_WIDTH_CHARS:
        text = text.replace(char, "")
    return text


def normalize_homoglyphs(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    return "".join(_HOMOGLYPH_MAP.get(char, char) for char in text)


def normalize_leetspeak(text: str) -> str:
    """
    Reverse common digit/symbol-for-letter substitutions, but only
    inside tokens that already contain at least two real letters.
    "1gn0r3" (3 real letters: g, n, r) gets normalized; "10.0.0.20",
    "5715", "8080" (zero real letters) are left untouched.
    """

    tokens = text.split(" ")
    normalized_tokens = []

    for token in tokens:
        letter_count = sum(1 for char in token if char.isalpha())

        if letter_count >= 2:
            normalized_tokens.append(token.translate(_LEET_MAP))
        else:
            normalized_tokens.append(token)

    return " ".join(normalized_tokens)


def normalize_for_detection(text: str) -> str:
    """Apply all detection-only normalizations."""

    text = strip_zero_width(text)
    text = normalize_homoglyphs(text)
    text = normalize_leetspeak(text)
    return text
