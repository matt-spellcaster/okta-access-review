import pytest


@pytest.fixture(autouse=True)
def no_real_email(monkeypatch):
    """Never send real email from tests, even if the shell has email settings."""
    monkeypatch.delenv("REPORT_EMAIL_TO", raising=False)
