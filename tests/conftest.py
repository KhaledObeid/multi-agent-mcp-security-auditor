"""Loaded by pytest before any test file. OWNER: Member A.

Force OFFLINE mode for the whole test session, before any test imports the
package (config.py reads the setting once, at import time). Without this, the
result depended on which test file happened to import the package first, and a
developer's .env with OFFLINE=0 made the graph tests call the real Gemini API.
python-dotenv does not override variables that are already set, so this wins.
"""
import os

os.environ["MCP_SECURITY_AUDITOR_OFFLINE"] = "1"
