"""Runtime configuration, read from environment variables (or a .env file)."""
import os

from dotenv import load_dotenv

load_dotenv()


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


class Settings:
    # Secret — lives only on the server, never sent to the browser.
    anthropic_api_key: str = os.getenv("ANTHROPIC_API_KEY", "")
    model: str = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5")
    max_output_tokens: int = _int("MAX_OUTPUT_TOKENS", 4096)

    # Abuse / cost protection.
    max_input_chars: int = _int("MAX_INPUT_CHARS", 100_000)
    max_followup_chars: int = _int("MAX_FOLLOWUP_CHARS", 2_000)
    max_history_messages: int = _int("MAX_HISTORY_MESSAGES", 12)
    rate_limit_requests: int = _int("RATE_LIMIT_REQUESTS", 20)
    rate_limit_window_seconds: int = _int("RATE_LIMIT_WINDOW_SECONDS", 60)


settings = Settings()
