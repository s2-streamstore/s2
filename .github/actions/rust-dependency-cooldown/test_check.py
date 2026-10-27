from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "cooldown_check", Path(__file__).with_name("check.py")
)
assert SPEC is not None and SPEC.loader is not None
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)

NOW = datetime(2026, 9, 16, tzinfo=timezone.utc)
APPROVED_EXCEPTION = {
    "crate": "rustls",
    "version": "0.23.45",
    "advisory": "https://rustsec.org/advisories/RUSTSEC-2026-0285.html",
    "reason": "First release fixing TLS 1.3 handshake encryption-level validation.",
}


def exception_document(*entries: dict[str, object]) -> str:
    return "\n".join(
        "[[exception]]\n"
        + "\n".join(f"{name} = {json.dumps(value)}" for name, value in entry.items())
        + "\n"
        for entry in entries
    )


class CooldownSecurityExceptionTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        temporary_root = Path(temporary_directory.name)
        self.repo = temporary_root / "consumer"
        self.repo.mkdir()
        self.action = temporary_root / "trusted-action"
        self.action.mkdir()
        self.exceptions = self.action / "security-exceptions.toml"
        self.exceptions.write_text(exception_document(APPROVED_EXCEPTION))
        (self.action / "first-party-crates.txt").write_text("s2-api\n")
        (self.repo / ".cargo").mkdir()
        (self.repo / ".cargo" / "config.toml").write_text(
            '[registry]\nglobal-min-publish-age = "7 days"\n'
        )
        self.write_lock()
        self.git("init", "--quiet")
        self.commit()

    def git(self, *arguments: str) -> None:
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Cooldown Tests",
                "-c",
                "user.email=cooldown-tests@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                *arguments,
            ],
            cwd=self.repo,
            check=True,
            capture_output=True,
            text=True,
        )

    def commit(self) -> None:
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "test: record baseline")

    def write_lock(self, *packages: tuple[str, str, str]) -> None:
        contents = "version = 3\n"
        for name, version, source in packages:
            contents += (
                "\n[[package]]\n"
                f"name = {json.dumps(name)}\n"
                f"version = {json.dumps(version)}\n"
                f"source = {json.dumps(source)}\n"
            )
        (self.repo / "Cargo.lock").write_text(contents)

    def run_gate(
        self,
        publication_times: dict[str, dict[str, datetime]] | None = None,
    ) -> tuple[int, str, str, list[str]]:
        published = publication_times or {
            "rustls": {"0.23.45": NOW - timedelta(days=1)},
        }
        output, errors = io.StringIO(), io.StringIO()
        with ExitStack() as stack:
            for name, value in {
                "ACTION_ROOT": self.action,
                "REPO_ROOT": self.repo,
                "CONFIG": self.repo / ".cargo" / "config.toml",
                "ALLOWLIST": self.action / "first-party-crates.txt",
                "SECURITY_EXCEPTIONS": self.exceptions,
            }.items():
                stack.enter_context(patch.object(check, name, value))
            stack.enter_context(
                patch.object(sys, "argv", ["check.py", "--repo-root", str(self.repo), "HEAD"])
            )
            clock = stack.enter_context(patch.object(check, "datetime", wraps=datetime))
            clock.now.return_value = NOW
            lookup = stack.enter_context(
                patch.object(check, "publication_times", side_effect=published.__getitem__)
            )
            stack.enter_context(redirect_stdout(output))
            stack.enter_context(redirect_stderr(errors))
            status = check.main()
        lookups = [call.args[0] for call in lookup.call_args_list]
        return status, output.getvalue(), errors.getvalue(), lookups

    def test_exact_security_exception_passes_and_reports_justification(self) -> None:
        self.write_lock(("rustls", "0.23.45", check.CRATES_IO_SOURCE))
        status, output, errors, _ = self.run_gate()
        self.assertEqual(status, 0, errors)
        for field in APPROVED_EXCEPTION.values():
            self.assertIn(field, output)

    def test_exception_does_not_cover_another_version_or_crate(self) -> None:
        for name, version in [("rustls", "0.23.46"), ("another-crate", "0.23.45")]:
            with self.subTest(crate=name, version=version):
                self.write_lock((name, version, check.CRATES_IO_SOURCE))
                status, _, errors, _ = self.run_gate(
                    {name: {version: NOW - timedelta(days=1)}}
                )
                self.assertEqual(status, 1)
                self.assertIn(f"{name} {version}", errors)

    def test_exception_does_not_hide_an_unrelated_young_dependency(self) -> None:
        self.write_lock(
            ("rustls", "0.23.45", check.CRATES_IO_SOURCE),
            ("another-crate", "1.0.0", check.CRATES_IO_SOURCE),
        )
        status, output, errors, _ = self.run_gate(
            {
                "rustls": {"0.23.45": NOW - timedelta(days=1)},
                "another-crate": {"1.0.0": NOW - timedelta(days=1)},
            }
        )
        self.assertEqual(status, 1)
        self.assertIn(APPROVED_EXCEPTION["advisory"], output)
        self.assertIn("another-crate 1.0.0", errors)
        self.assertNotIn("rustls 0.23.45", errors)

    def test_consumer_repository_cannot_supply_its_own_exception(self) -> None:
        unapproved = {**APPROVED_EXCEPTION, "version": "0.23.46"}
        consumer_action = self.repo / ".github" / "actions" / "rust-dependency-cooldown"
        consumer_action.mkdir(parents=True)
        for directory in [self.repo, self.repo / ".cargo", consumer_action]:
            (directory / "security-exceptions.toml").write_text(exception_document(unapproved))
        self.write_lock(("rustls", "0.23.46", check.CRATES_IO_SOURCE))
        status, _, errors, _ = self.run_gate(
            {"rustls": {"0.23.46": NOW - timedelta(days=1)}}
        )
        self.assertEqual(status, 1)
        self.assertIn("rustls 0.23.46", errors)

    def test_malformed_security_exceptions_fail_closed(self) -> None:
        documents = {
            "invalid TOML": "[[exception]",
            "not an array": "exception = 1\n",
            "not a table": "exception = [1]\n",
            "unknown top-level field": "exceptions = []\n",
        }
        for field in APPROVED_EXCEPTION:
            missing = {name: value for name, value in APPROVED_EXCEPTION.items() if name != field}
            documents[f"missing {field}"] = exception_document(missing)
            for value in ["", "   ", 123, f" {APPROVED_EXCEPTION[field]}"]:
                documents[f"invalid {field}: {value!r}"] = exception_document(
                    {**APPROVED_EXCEPTION, field: value}
                )
        documents["unknown field"] = exception_document({**APPROVED_EXCEPTION, "extra": "value"})
        documents["duplicate pair"] = exception_document(APPROVED_EXCEPTION, APPROVED_EXCEPTION)
        self.write_lock(("rustls", "0.23.45", check.CRATES_IO_SOURCE))
        for description, document in documents.items():
            with self.subTest(description=description):
                self.exceptions.write_text(document)
                status, _, errors, _ = self.run_gate()
                self.assertEqual(status, 2)
                self.assertIn("minimum-publish-age error", errors)

    def test_missing_action_exception_file_fails_closed(self) -> None:
        self.exceptions.unlink()
        self.write_lock(("rustls", "0.23.45", check.CRATES_IO_SOURCE))
        status, _, errors, _ = self.run_gate()
        self.assertEqual(status, 2)
        self.assertIn("minimum-publish-age error", errors)

    def test_malformed_exceptions_fail_even_when_no_lockfile_changed(self) -> None:
        self.exceptions.write_text("[[exception]")
        status, _, errors, _ = self.run_gate()
        self.assertEqual(status, 2)
        self.assertIn("minimum-publish-age error", errors)

    def test_empty_exception_lists_do_not_exempt_young_dependencies(self) -> None:
        self.write_lock(("rustls", "0.23.45", check.CRATES_IO_SOURCE))
        for document in ["", "exception = []\n"]:
            with self.subTest(document=document):
                self.exceptions.write_text(document)
                status, _, errors, _ = self.run_gate()
                self.assertEqual(status, 1)
                self.assertIn("rustls 0.23.45", errors)

    def test_exception_ranges_and_wildcards_are_rejected(self) -> None:
        self.write_lock(("rustls", "0.23.45", check.CRATES_IO_SOURCE))
        for field, value in [
            ("crate", "rustls*"),
            ("version", "*"),
            ("version", "0.23.*"),
            ("version", ">=0.23.45"),
        ]:
            with self.subTest(field=field, value=value):
                self.exceptions.write_text(
                    exception_document({**APPROVED_EXCEPTION, field: value})
                )
                status, _, errors, _ = self.run_gate()
                self.assertEqual(status, 2)
                self.assertIn("minimum-publish-age error", errors)

    def test_approved_version_still_requires_a_publication_time(self) -> None:
        self.write_lock(("rustls", "0.23.45", check.CRATES_IO_SOURCE))
        status, _, errors, _ = self.run_gate({"rustls": {}})
        self.assertEqual(status, 2)
        self.assertIn("no publication time for rustls 0.23.45", errors)

    def test_mature_approved_version_uses_normal_age_check(self) -> None:
        self.write_lock(("rustls", "0.23.45", check.CRATES_IO_SOURCE))
        status, output, errors, lookups = self.run_gate(
            {"rustls": {"0.23.45": NOW - timedelta(days=7)}}
        )
        self.assertEqual(status, 0, errors)
        self.assertNotIn(APPROVED_EXCEPTION["advisory"], output)
        self.assertEqual(lookups, ["rustls"])

    def test_age_boundary_for_ordinary_dependencies_is_unchanged(self) -> None:
        self.write_lock(("another-crate", "1.0.0", check.CRATES_IO_SOURCE))
        for age, expected_status in [(timedelta(days=7), 0), (timedelta(days=7, seconds=-1), 1)]:
            with self.subTest(age=age):
                status, _, errors, _ = self.run_gate({"another-crate": {"1.0.0": NOW - age}})
                self.assertEqual(status, expected_status, errors)

    def test_first_party_allowlist_still_exempts_new_versions(self) -> None:
        self.write_lock(("s2-api", "99.0.0", check.CRATES_IO_SOURCE))
        status, _, errors, lookups = self.run_gate()
        self.assertEqual(status, 0, errors)
        self.assertEqual(lookups, [])

    def test_other_sources_are_not_processed_as_security_exceptions(self) -> None:
        for source in [
            "registry+https://example.invalid/index",
            "git+https://example.invalid/rustls",
        ]:
            with self.subTest(source=source):
                self.write_lock(("rustls", "0.23.45", source))
                status, output, errors, lookups = self.run_gate()
                self.assertEqual(status, 0, errors)
                self.assertNotIn(APPROVED_EXCEPTION["advisory"], output)
                self.assertEqual(lookups, [])

    def test_existing_locked_versions_are_not_rechecked(self) -> None:
        self.write_lock(("already-locked", "1.0.0", check.CRATES_IO_SOURCE))
        self.commit()
        self.write_lock(
            ("already-locked", "1.0.0", check.CRATES_IO_SOURCE),
            ("another-crate", "1.0.0", check.CRATES_IO_SOURCE),
        )
        status, _, errors, lookups = self.run_gate(
            {"another-crate": {"1.0.0": NOW - timedelta(days=8)}}
        )
        self.assertEqual(status, 0, errors)
        self.assertEqual(lookups, ["another-crate"])


if __name__ == "__main__":
    unittest.main()
