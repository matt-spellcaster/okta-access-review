import json
from collections import defaultdict
from datetime import date
from pathlib import Path

import pytest

from access_review.checks import CHECKS, Config, ReviewContext, run_checks
from access_review.models import Snapshot
from access_review.roster import load_roster

FIXTURES = Path(__file__).parent.parent / "fixtures"
AS_OF = date(2026, 9, 15)


@pytest.fixture
def demo():
    snapshot = Snapshot.from_dict(json.loads((FIXTURES / "demo_snapshot.json").read_text()))
    roster = load_roster(FIXTURES / "demo_roster.csv")
    config = Config.load(FIXTURES / "demo_config.json")
    return ReviewContext(snapshot, roster, config, AS_OF)


def by_check(findings):
    result = defaultdict(set)
    for f in findings:
        result[f.check_id].add(f.subject.split("@")[0])
    return dict(result)


def test_demo_findings_are_exactly_the_planted_ones(demo):
    findings, skipped = run_checks(demo)
    assert skipped == []
    assert by_check(findings) == {
        "AR-01": {"marcus.lee"},
        "AR-02": {"sofia.ramos"},
        "AR-03": {"jordan.kim"},
        "AR-04": {"lee.chen"},
        "AR-05": {"hannah.ortiz"},
        "AR-06": {"omar.haddad"},
        "AR-07": {"sofia.ramos"},
        "AR-08": {"grace.park"},
        "AR-09": {"victor.nguyen"},
        "AR-10": {"Terraform Automation"},
        "AR-11": {"priya.shah"},
    }


def test_every_check_is_covered_by_the_demo(demo):
    findings, _ = run_checks(demo)
    assert {c.id for c in CHECKS} == {f.check_id for f in findings}


def test_findings_sorted_most_severe_first(demo):
    findings, _ = run_checks(demo)
    assert findings[0].severity == "critical"
    assert findings[-1].severity == "info"


def test_roster_checks_skipped_without_roster(demo):
    demo.roster = None
    findings, skipped = run_checks(demo)
    assert skipped == ["AR-01", "AR-02", "AR-03"]
    assert not {"AR-01", "AR-02", "AR-03"} & {f.check_id for f in findings}


def test_without_roster_contractor_type_comes_from_okta_profile(demo):
    demo.roster = None
    findings, _ = run_checks(demo)
    assert by_check(findings)["AR-07"] == {"sofia.ramos"}


def test_service_account_not_reported_as_missing_from_hr(demo):
    demo.config.service_accounts = []
    findings, _ = run_checks(demo)
    assert "svc-ci" in by_check(findings)["AR-03"]


def test_unknown_mfa_is_info_not_high(demo):
    lee = next(u for u in demo.snapshot.users if u.login.startswith("lee.chen"))
    lee.factors = None
    findings, _ = run_checks(demo)
    [f] = [f for f in findings if f.check_id == "AR-04"]
    assert f.severity == "info"


def test_inactive_threshold_is_configurable(demo):
    demo.config.inactive_days = 200
    findings, _ = run_checks(demo)
    assert "AR-05" not in by_check(findings)


def test_suspended_user_without_access_is_clean(demo):
    findings, _ = run_checks(demo)
    assert not [f for f in findings if f.subject.startswith("nina.patel")]


def test_config_rejects_unknown_keys(tmp_path):
    path = tmp_path / "c.json"
    path.write_text('{"inactive_dayz": 30}')
    with pytest.raises(ValueError, match="inactive_dayz"):
        Config.load(path)
