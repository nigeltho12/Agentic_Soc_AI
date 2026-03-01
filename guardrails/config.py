"""Configuration loader.

API keys/secrets must be provided via environment variables or a .env file.
Never commit real secrets to source control.
"""

import os
from dotenv import load_dotenv

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
LOG_ANALYTICS_WORKSPACE_ID = os.getenv("LOG_ANALYTICS_WORKSPACE_ID", "")

def require(var_name: str, value: str) -> str:
    if not value:
        raise RuntimeError(f"Missing required environment variable: {var_name}")
    return value
