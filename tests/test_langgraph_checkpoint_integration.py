"""Integration test for LangGraph Checkpoint and Resume Cycles."""

from __future__ import annotations

import os
import sys

SCRATCH_DIR = "/home/shadow777/.gemini/antigravity/brain/acd344e7-b52c-4dd9-ade4-35eb9e9f1abe/scratch"
if SCRATCH_DIR not in sys.path:
    sys.path.insert(0, SCRATCH_DIR)

from test_langgraph_integration import run_langgraph_checkpoint_suite


def test_langgraph_checkpoint_and_resume_suite():
    res = run_langgraph_checkpoint_suite()
    assert res["all_passed"] is True, f"Failed tests: {[r for r in res['results'] if not r['passed']]}"
    assert res["total_tests"] == 7
    assert res["passed_tests"] == 7

