"""Unit tests for Broker API JWT enforcement and Security Watchdog Tier 1A/1B controls."""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, rel_path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class TestSecurityControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        os.environ["LINKERS_PROJECT_ID"] = "partner-billing-linkers-prod"
        os.environ["ALLOWED_BILLING_PRINCIPALS"] = "group:gcp-billing-pam-admins@partner.com"
        cls.watchdog = load_module("watchdog_main", "services/security-watchdog/main.py")
        cls.broker = load_module("broker_main", "services/broker-api/main.py")

    def test_watchdog_tier1b_blocks_external_gmail_and_rogue_sa(self) -> None:
        # Must block disposable consumer accounts
        self.assertFalse(self.watchdog.is_authorized_billing_member("user:attacker@gmail.com"))
        # Must block external attacker service accounts (even though they end with .iam.gserviceaccount.com!)
        self.assertFalse(
            self.watchdog.is_authorized_billing_member(
                "serviceAccount:evil@attacker-made-for-abuse.iam.gserviceaccount.com"
            )
        )
        # Must block non-linker SAs even inside the linkers project
        self.assertFalse(
            self.watchdog.is_authorized_billing_member(
                "serviceAccount:other-sa@partner-billing-linkers-prod.iam.gserviceaccount.com"
            )
        )

    def test_watchdog_tier1b_allows_isolated_linker_sa_and_pam_group(self) -> None:
        self.assertTrue(
            self.watchdog.is_authorized_billing_member(
                "serviceAccount:sa-linker-cust01@partner-billing-linkers-prod.iam.gserviceaccount.com"
            )
        )
        self.assertTrue(
            self.watchdog.is_authorized_billing_member("group:gcp-billing-pam-admins@partner.com")
        )

    def test_broker_defaults_to_jwt_enforcement(self) -> None:
        self.assertEqual(self.broker.AUTH_MODE, "ENFORCE_JWT")
        self.assertEqual(self.broker.app.version, "1.1.0")


if __name__ == "__main__":
    unittest.main()
