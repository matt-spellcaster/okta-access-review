import pytest


@pytest.fixture(autouse=True)
def no_real_email(monkeypatch):
    """Never send real email or Slack messages from tests, even if the shell has settings."""
    monkeypatch.delenv("REPORT_EMAIL_TO", raising=False)
    for name in ("SLACK_WEBHOOK_URL", "SLACK_BOT_TOKEN", "SLACK_CHANNEL_ID", "SLACK_ATTACH_PDF"):
        monkeypatch.delenv(name, raising=False)
