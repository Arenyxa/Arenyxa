from __future__ import annotations

"""Auditable Phase 1 architecture, lifecycle, dependency and failure contracts.

This module is deliberately descriptive rather than a second runtime.  It gives tests,
review tooling and later phases one canonical place to ask who owns a subsystem, which
layers it may depend on, and what a failure is allowed to do.
"""
