"""
Unit tests for the Slopsquatting Detector agent.
"""

from unittest.mock import MagicMock

from zak.agents.slopsquatting.agent import SlopsquattingDetectorAgent
from zak.agents.slopsquatting.tools import (
    check_npm_package,
    check_pypi_package,
    extract_imports,
)
from zak.core.runtime.agent import AgentContext
from zak.core.tools.builtins import read_local_code_file


def test_slopsquatting_system_prompt() -> None:
    """Test that the system prompt includes the tenant ID and target file."""
    agent = SlopsquattingDetectorAgent()

    mock_dsl = MagicMock()
    context = AgentContext(
        tenant_id="test_tenant",
        trace_id="test_trace",
        environment="test",
        dsl=mock_dsl,
        metadata={"target_file": "src/app.py"},
    )

    prompt = agent.system_prompt(context)

    assert "test_tenant" in prompt
    assert "src/app.py" in prompt
    assert "extract_imports" in prompt
    assert "check_pypi_package" in prompt
    assert "check_npm_package" in prompt


def test_slopsquatting_tools() -> None:
    """Test that the agent exposes exactly 4 tools."""
    agent = SlopsquattingDetectorAgent()
    tools = agent.tools

    assert len(tools) == 4
    assert read_local_code_file in tools
    assert extract_imports in tools
    assert check_pypi_package in tools
    assert check_npm_package in tools


def test_extract_imports_python() -> None:
    """Test import extraction from Python source code."""
    source = """
import requests
import os
import sys
from flask import Flask
from dataprocessorx import transform
import pandas as pd
from json import loads
"""
    result = extract_imports(source_code=source, file_path="app.py")

    assert result["language"] == "python"
    assert "requests" in result["packages"]
    assert "flask" in result["packages"]
    assert "dataprocessorx" in result["packages"]
    assert "pandas" in result["packages"]
    # stdlib should be filtered out
    assert "os" not in result["packages"]
    assert "sys" not in result["packages"]
    assert "json" not in result["packages"]


def test_extract_imports_javascript() -> None:
    """Test import extraction from JavaScript source code."""
    source = """
const express = require('express');
const fs = require('fs');
import React from 'react';
import { useState } from 'react';
import '@scope/pkg';
import './local-module';
"""
    result = extract_imports(source_code=source, file_path="app.js")

    assert result["language"] == "javascript"
    assert "express" in result["packages"]
    assert "react" in result["packages"]
    assert "@scope/pkg" in result["packages"]
    # builtins and relative imports should be filtered
    assert "fs" not in result["packages"]
    assert "./local-module" not in result["packages"]


def test_extract_imports_filters_stdlib() -> None:
    """Verify that Python stdlib modules are excluded from results."""
    source = """
import os
import sys
import json
import pathlib
import hashlib
import collections
"""
    result = extract_imports(source_code=source, file_path="utils.py")

    assert result["language"] == "python"
    assert result["packages"] == []
    assert result["count"] == 0
