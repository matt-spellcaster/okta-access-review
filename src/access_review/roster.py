"""HR roster: the source of truth for who should have an account.

CSV columns: email, name, employment_type, status, end_date, manager
  employment_type: employee | contractor
  status:          active | leave | terminated
  end_date:        YYYY-MM-DD (termination date or contract end), optional
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import date
from pathlib import Path


@dataclass
class RosterEntry:
    email: str
    name: str
    employment_type: str
    status: str
    end_date: date | None
    manager: str

    def is_gone(self, as_of: date) -> bool:
        return self.status == "terminated" or (self.end_date is not None and self.end_date < as_of)


def entry_for(roster: dict[str, RosterEntry] | None, email: str, login: str) -> RosterEntry | None:
    """Match an Okta user to their HR record. The collector and the checks both
    need this, and they have to agree on it."""
    if roster is None:
        return None
    return roster.get(email) or roster.get(login.lower())


def load_roster(path: Path) -> dict[str, RosterEntry]:
    entries = {}
    with path.open(newline="") as f:
        for row in csv.DictReader(f):
            email = row["email"].strip().lower()
            end = (row.get("end_date") or "").strip()
            entries[email] = RosterEntry(
                email=email,
                name=(row.get("name") or "").strip(),
                employment_type=(row.get("employment_type") or "employee").strip().lower(),
                status=(row.get("status") or "active").strip().lower(),
                end_date=date.fromisoformat(end) if end else None,
                manager=(row.get("manager") or "").strip(),
            )
    return entries
