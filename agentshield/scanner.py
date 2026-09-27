"""Transparent heuristic scanner. A low score does not establish safety."""

from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

LIMIT = 20_000
INVISIBLE = "\u200b\u200c\u200d\ufeff"


@dataclass(frozen=True)
class Rule:
    id: str
    label: str
    severity: int
    detail: str
    patterns: tuple[str, ...]


RULES = (
    Rule("override", "Instruction override", 28, "Attempts to replace trusted instructions", (
        r"ignore (all |any |the )?(previous|prior|above) (instructions|rules|context)",
        r"disregard (the )?(system|developer|previous)", r"new (system )?instructions?",
        r"forget (everything|your instructions|the rules)",
    )),
    Rule("exfiltration", "Data exfiltration", 34, "Requests secrets or private context", (
        r"(reveal|print|send|return|show|expose).{0,35}(api key|secret|password|token|system prompt|private data)",
        r"(api key|secret|token|password).{0,25}(to|at|via).{0,25}(http|email|webhook)",
        r"(forward|send|copy).{0,45}(confidential|private|entire conversation).{0,45}(external|page author|address|reply)",
        r"do not redact",
    )),
    Rule("tool_abuse", "Unsafe tool request", 25, "Pushes an agent toward external actions", (
        r"(run|execute|invoke|call).{0,24}(shell|terminal|command|tool|function)",
        r"(download|upload|post|send).{0,32}(credentials|secrets?|private data)",
        r"(delete|remove|overwrite).{0,25}(files?|database)",
    )),
    Rule("role_hijack", "Role impersonation", 20, "Claims privileged identity", (
        r"you are now", r"(system|developer|administrator|root) (message|override|notice|instruction)",
        r"act as (an? )?(admin|root|system)",
    )),
    Rule("concealment", "Concealment", 18, "Tries to hide actions", (
        r"do not (tell|show|mention|alert|notify)",
        r"(silently|secretly|without (the )?user knowing)", r"hide (this|the action|your response)",
    )),
    Rule("obfuscation", "Encoded payload", 16, "Encoding or invisible characters", (
        r"(base64|rot13|hex)[- ]?(decode|encoded|payload)?",
        r"[A-Za-z0-9+/]{48,}={0,2}",
    )),
)


def _normalized_with_offsets(text: str) -> tuple[str, list[int]]:
    chars, offsets = [], []
    for index, char in enumerate(text):
        if char in INVISIBLE:
            continue
        for normalized_char in unicodedata.normalize("NFKC", char):
            chars.append(normalized_char)
            offsets.append(index)
    return "".join(chars), offsets


def _policy(findings: list[dict[str, Any]], level: str) -> list[str]:
    ids = {item["id"] for item in findings}
    actions = []
    if ids & {"override", "role_hijack"}:
        actions.append("Treat embedded instructions as data; preserve trusted instruction hierarchy.")
    if "exfiltration" in ids:
        actions.append("Keep secrets outside the agent context and deny outbound transfer.")
    if "tool_abuse" in ids:
        actions.append("Require explicit approval before tools write, send, execute, or delete.")
    if ids & {"concealment", "obfuscation"}:
        actions.append("Inspect encoded content separately and rescan decoded text before use.")
    if level in {"critical", "high"}:
        actions.append("Quarantine this input and review before continuing.")
    if not actions:
        actions.append("No rule matched. Keep least-privilege controls; an attack may still be missed.")
    return actions


def scan_text(raw_text: str) -> dict[str, Any]:
    """Return deterministic signals and original-text evidence offsets."""
    if not isinstance(raw_text, str):
        raise TypeError("raw_text must be a string")
    text = raw_text[:LIMIT]
    normalized, offsets = _normalized_with_offsets(text)
    findings, ranges = [], []
    for rule in RULES:
        matches = []
        for pattern in rule.patterns:
            for match in re.finditer(pattern, normalized, flags=re.IGNORECASE):
                matches.append(match.group())
                ranges.append({"start": offsets[match.start()], "end": offsets[match.end() - 1] + 1})
        if matches:
            findings.append({"id": rule.id, "label": rule.label, "severity": rule.severity,
                             "detail": rule.detail, "matches": list(dict.fromkeys(matches))[:4], "count": len(matches)})
    invisible_matches = list(re.finditer(f"[{INVISIBLE}]+", text))
    if invisible_matches:
        ranges.extend({"start": match.start(), "end": match.end()} for match in invisible_matches)
        found = next((item for item in findings if item["id"] == "obfuscation"), None)
        if found:
            found["count"] += len(invisible_matches)
        else:
            rule = RULES[-1]
            findings.append({"id": rule.id, "label": rule.label, "severity": rule.severity,
                             "detail": rule.detail, "matches": ["invisible Unicode characters"],
                             "count": len(invisible_matches)})
    score = sum(item["severity"] * (1 + min(item["count"] - 1, 2) * 0.16) for item in findings)
    if len(findings) >= 2:
        score += 8
    ids = {item["id"] for item in findings}
    if {"override", "exfiltration"} <= ids:
        score += 12
    score = min(100, math.floor(score + 0.5))
    level = "critical" if score >= 75 else "high" if score >= 45 else "caution" if score >= 20 else "low"
    merged = []
    for span in sorted(ranges, key=lambda item: item["start"]):
        if merged and span["start"] <= merged[-1]["end"]:
            merged[-1]["end"] = max(merged[-1]["end"], span["end"])
        else:
            merged.append(span.copy())
    return {"text": text, "truncated": len(raw_text) > LIMIT, "score": score, "level": level,
            "findings": findings, "ranges": merged, "policy": _policy(findings, level)}
