"""Optional caller-side gate. It cannot identify attacks outside its rules."""

from .scanner import scan_text


def gate_untrusted_content(text: str) -> dict:
    report = scan_text(text)
    if report["truncated"]:
        return {"decision": "quarantine", "content": None, "report": report,
                "reason": "Input exceeds scan limit"}
    if report["score"] >= 20:
        return {"decision": "review", "content": None, "report": report,
                "reason": "Review detected signals before forwarding"}
    return {"decision": "pass", "content": report["text"], "report": report,
            "reason": "No rule matched; maintain independent tool permissions"}
