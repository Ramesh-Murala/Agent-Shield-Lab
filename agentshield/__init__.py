"""Explainable prompt-injection signals for untrusted agent inputs."""

from .gate import gate_untrusted_content
from .scanner import scan_text

__all__ = ["gate_untrusted_content", "scan_text"]
