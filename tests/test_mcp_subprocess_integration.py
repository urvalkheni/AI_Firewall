"""Integration test for Real MCP Server Subprocess over stdio transport."""

from __future__ import annotations

import os
import sys

# Ensure scratch path is loadable for integration runner
SCRATCH_DIR = "/home/shadow777/.gemini/antigravity/brain/acd344e7-b52c-4dd9-ade4-35eb9e9f1abe/scratch"
if SCRATCH_DIR not in sys.path:
    sys.path.insert(0, SCRATCH_DIR)

from test_mcp_real_subprocess import run_mcp_real_subprocess_suite


def test_mcp_real_subprocess_stdio_suite():
    res = run_mcp_real_subprocess_suite()
    assert res["all_passed"] is True, f"Failed tests: {[r for r in res['results'] if not r['passed']]}"
    assert res["total_tests"] == 9
    assert res["passed_tests"] == 9

