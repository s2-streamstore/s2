#!/usr/bin/env python3
"""Reject newly locked crates.io versions that are too new."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG = REPO_ROOT / ".cargo" / "config.toml"
ALLOWLIST = Path(__file__).with_name("rust-min-publish-age-allowlist.txt")
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
INDEX_BASE = "https://index.crates.io"
USER_AGENT = "s2 minimum-publish-age check (github.com/s2-streamstore/s2)"
RETRY_ATTEMPTS = 4
RETRY_BASE_DELAY_SECONDS = 2
UNIT_SECONDS = {
    "second": 1,
    "seconds": 1,
    "minute": 60,
    "minutes": 60,
    "hour": 3600,
    "hours": 3600,
    "day": 86400,
    "days": 86400,
    "week": 604800,
    "weeks": 604800,
    "month": 2592000,
    "months": 2592000,
}


def minimum_age() -> tuple[timedelta, str]:
    with CONFIG.open("rb") as config_file:
        raw = tomllib.load(config_file).get("registry", {}).get("global-min-publish-age")
    if not isinstance(raw, str):
        raise ValueError(f"registry.global-min-publish-age is not set in {CONFIG}")
    value = raw.strip()
    if value == "0":
        return timedelta(0), value
    match = re.fullmatch(r"(\d+)\s+(\w+)", value)
    if match is None or match.group(2) not in UNIT_SECONDS:
        raise ValueError(f"cannot parse global-min-publish-age = {value!r}")
    return timedelta(seconds=int(match.group(1)) * UNIT_SECONDS[match.group(2)]), value


def allowed_crates() -> set[str]:
    return {
        name
        for line in ALLOWLIST.read_text().splitlines()
        if (name := line.split("#", 1)[0].strip())
    }


def crates_io_versions(lock_text: str) -> set[tuple[str, str]]:
    packages = tomllib.loads(lock_text).get("package", [])
    return {
        (package["name"], package["version"])
        for package in packages
        if package.get("source") == CRATES_IO_SOURCE
    }


def run_git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def lock_at(revision: str, path: str) -> str | None:
    result = run_git("show", f"{revision}:{path}")
    return result.stdout if result.returncode == 0 else None


def index_url(name: str) -> str:
    normalized = name.lower()
    if len(normalized) == 1:
        path = f"1/{normalized}"
    elif len(normalized) == 2:
        path = f"2/{normalized}"
    elif len(normalized) == 3:
        path = f"3/{normalized[0]}/{normalized}"
    else:
        path = f"{normalized[:2]}/{normalized[2:4]}/{normalized}"
    return f"{INDEX_BASE}/{path}"


def fetch_index(name: str) -> str:
    request = urllib.request.Request(index_url(name), headers={"User-Agent": USER_AGENT})
    last_error: Exception | None = None
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        if attempt > 1:
            time.sleep(RETRY_BASE_DELAY_SECONDS * (attempt - 1))
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read()
        except urllib.error.HTTPError as error:
            if error.code < 500 and error.code != 429:
                raise RuntimeError(f"cannot read the crates.io index for {name}: {error}") from error
            last_error = error
            continue
        except (urllib.error.URLError, TimeoutError) as error:
            last_error = error
            continue
        try:
            return raw.decode()
        except UnicodeDecodeError as error:
            raise RuntimeError(f"cannot read the crates.io index for {name}: {error}") from error
    raise RuntimeError(
        f"cannot read the crates.io index for {name} after {RETRY_ATTEMPTS} attempts: {last_error}"
    ) from last_error


def publication_times(name: str) -> dict[str, datetime]:
    times: dict[str, datetime] = {}
    for line in fetch_index(name).splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        if pubtime := entry.get("pubtime"):
            times[entry["vers"]] = datetime.fromisoformat(pubtime.replace("Z", "+00:00"))
    return times


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "base_ref",
        nargs="?",
        help="check only crates.io versions not present at this Git ref",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        age_limit, age_text = minimum_age()
        allowlist = allowed_crates()
        if args.base_ref and run_git("rev-parse", "--verify", "--quiet", args.base_ref).returncode:
            raise ValueError(f"base ref {args.base_ref!r} is not available")

        lockfile_result = run_git("ls-files", "*Cargo.lock")
        if lockfile_result.returncode:
            raise RuntimeError(f"cannot list Cargo.lock files: {lockfile_result.stderr.strip()}")
        lockfiles = lockfile_result.stdout.splitlines()
        now = datetime.now(timezone.utc)
        violations: list[str] = []
        checked = 0
        index_cache: dict[str, dict[str, datetime]] = {}

        for lockfile in sorted(lockfiles):
            proposed = crates_io_versions((REPO_ROOT / lockfile).read_text())
            baseline: set[tuple[str, str]] = set()
            if args.base_ref and (text := lock_at(args.base_ref, lockfile)) is not None:
                baseline = crates_io_versions(text)

            for name, version in sorted(proposed - baseline):
                if name in allowlist:
                    continue
                if name not in index_cache:
                    index_cache[name] = publication_times(name)
                pubtime = index_cache[name].get(version)
                if pubtime is None:
                    raise RuntimeError(f"no publication time for {name} {version}")
                checked += 1
                crate_age = now - pubtime
                if crate_age < age_limit:
                    violations.append(
                        f"{name} {version} ({lockfile}): published "
                        f"{crate_age.total_seconds() / 86400:.1f} days ago; "
                        f"minimum is {age_text}"
                    )
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        print(f"minimum-publish-age error: {error}", file=sys.stderr)
        return 2

    if violations:
        print("New crates.io versions are inside the publication cooldown:", file=sys.stderr)
        for violation in violations:
            print(f"  - {violation}", file=sys.stderr)
        return 1

    print(f"Checked {checked} new crates.io version(s); all are at least {age_text} old.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
