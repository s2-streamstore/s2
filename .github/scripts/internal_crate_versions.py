#!/usr/bin/env python3
"""Keep the workspace's own crates consistent with each other across releases.

check-requirements
    Every version requirement on a workspace crate must be that crate's exact
    current version. release-plz rewrites a requirement to each new version at the
    precision it is written with, so "0.32.2" becomes "0.32.3", but "0.32" never
    moves. A requirement that stays behind lets a newer crate resolve against an
    older sibling it can't compile with.

breaking-bumps --base REF [--apply]
    Workspace libraries use each other's types in their public APIs. When a
    published library gets a semver-breaking version bump since REF, every
    published library that depends on it, directly or transitively, needs one too.
    Otherwise its next release is a semver-compatible upgrade that doesn't compile
    with older siblings. Version groups from release-plz.toml move together.
    --apply sets the missing bumps with `release-plz set-version`.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import tomllib

DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
LIBRARY_KINDS = {"lib", "rlib", "dylib", "proc-macro"}


@dataclass
class Package:
    name: str
    version: str
    manifest: Path
    library: bool
    published: bool
    dependencies: set[str]


def parse_version(text: str) -> tuple[int, int, int]:
    core = text.split("+", 1)[0].split("-", 1)[0]
    major, minor, patch = (int(part) for part in core.split("."))
    return major, minor, patch


def is_breaking(old: str, new: str) -> bool:
    """Whether Cargo treats `new` as incompatible with `old` (caret semantics)."""
    o, n = parse_version(old), parse_version(new)
    if o[0] != n[0]:
        return True
    if o[0] == 0 and o[1] != n[1]:
        return True
    return o[0] == 0 and o[1] == 0 and o[2] != n[2]


def next_breaking(version: str) -> str:
    major, minor, patch = parse_version(version)
    if major:
        return f"{major + 1}.0.0"
    if minor:
        return f"0.{minor + 1}.0"
    return f"0.0.{patch + 1}"


def load_packages(root: Path) -> dict[str, Package]:
    metadata = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--no-deps", "--format-version", "1"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    members = {p["name"] for p in metadata["packages"]}
    return {
        p["name"]: Package(
            name=p["name"],
            version=p["version"],
            manifest=Path(p["manifest_path"]).resolve(),
            library=any(LIBRARY_KINDS & set(t["kind"]) for t in p["targets"]),
            published=p["publish"] != [],
            dependencies={
                d["name"]
                for d in p["dependencies"]
                if d.get("path") and d["kind"] is None and d["name"] in members
            },
        )
        for p in metadata["packages"]
    }


def version_groups(root: Path) -> dict[str, set[str]]:
    config = root / "release-plz.toml"
    if not config.exists():
        return {}
    groups: dict[str, set[str]] = {}
    for package in tomllib.loads(config.read_text()).get("package", []):
        if group := package.get("version_group"):
            groups.setdefault(group, set()).add(package["name"])
    return groups


def requirement_problems(root: Path, packages: dict[str, Package]) -> list[str]:
    by_dir = {p.manifest.parent: p for p in packages.values()}
    manifests = [root / "Cargo.toml", *(p.manifest for p in packages.values())]
    problems = []
    for manifest in dict.fromkeys(manifests):
        data = tomllib.loads(manifest.read_text())
        tables = [
            (
                "workspace.dependencies",
                data.get("workspace", {}).get("dependencies", {}),
            )
        ]
        tables += [(t, data.get(t, {})) for t in DEPENDENCY_TABLES]
        for target, target_data in data.get("target", {}).items():
            tables += [
                (f"target.{target}.{t}", target_data.get(t, {}))
                for t in DEPENDENCY_TABLES
            ]
        for table, deps in tables:
            for key, spec in deps.items():
                if (
                    not isinstance(spec, dict)
                    or "path" not in spec
                    or "version" not in spec
                ):
                    continue
                dep = by_dir.get((manifest.parent / spec["path"]).resolve())
                if dep and spec["version"] != dep.version:
                    problems.append(
                        f"{manifest.relative_to(root)} [{table}] {key}: version = "
                        f"{spec['version']!r}, expected {dep.version!r}, the current version of {dep.name}"
                    )
    return problems


def base_versions(
    root: Path, base: str, packages: dict[str, Package]
) -> dict[str, str]:
    def show(path: Path) -> dict | None:
        result = subprocess.run(
            ["git", "show", f"{base}:{path.relative_to(root).as_posix()}"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        return tomllib.loads(result.stdout) if result.returncode == 0 else None

    workspace = show(root / "Cargo.toml") or {}
    workspace_version = workspace.get("workspace", {}).get("package", {}).get("version")
    versions = {}
    for package in packages.values():
        manifest = show(package.manifest)
        if manifest is None:
            continue
        version = manifest.get("package", {}).get("version")
        if isinstance(version, dict) and version.get("workspace"):
            version = workspace_version
        if isinstance(version, str):
            versions[package.name] = version
    return versions


def required_bumps(
    packages: dict[str, Package], base: dict[str, str], groups: dict[str, set[str]]
) -> dict[str, tuple[str, str]]:
    """Map each package that needs a breaking bump to (version, reason)."""
    group_of = {
        member: group for group, members in groups.items() for member in members
    }
    required: dict[str, tuple[str, str]] = {}

    def current(name: str) -> str:
        return required[name][0] if name in required else packages[name].version

    def breaking(name: str) -> bool:
        return name in base and is_breaking(base[name], current(name))

    def group(name: str) -> list[str]:
        members = groups.get(group_of.get(name), {name})
        return sorted(m for m in members if m in packages and m in base)

    queue = [name for name in packages if packages[name].library and breaking(name)]
    seen = set(queue)
    while queue:
        dependency = queue.pop(0)
        cause = f"depends on {dependency} ({base[dependency]} -> {current(dependency)})"
        for package in packages.values():
            if dependency not in package.dependencies:
                continue
            if not (package.library and package.published) or package.name not in base:
                continue
            members = group(package.name)
            if not breaking(package.name):
                version = max(
                    (next_breaking(base[m]) for m in members), key=parse_version
                )
                for member in members:
                    if parse_version(current(member)) < parse_version(version):
                        reason = (
                            cause
                            if member == package.name
                            else f"shares version group {group_of[member]} with {package.name}"
                        )
                        required[member] = (version, reason)
            for member in members:
                if member not in seen and breaking(member):
                    seen.add(member)
                    queue.append(member)
    return required


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check-requirements")
    bumps = commands.add_parser("breaking-bumps")
    bumps.add_argument(
        "--base", required=True, help="Git ref holding the last released versions"
    )
    bumps.add_argument(
        "--apply", action="store_true", help="set the missing bumps with release-plz"
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    packages = load_packages(root)

    if args.command == "check-requirements":
        problems = requirement_problems(root, packages)
        for problem in problems:
            print(problem, file=sys.stderr)
        if problems:
            print(
                "Set each requirement to the crate's exact current version.",
                file=sys.stderr,
            )
            return 1
        print("Internal crate requirements match current versions.")
        return 0

    base = base_versions(root, args.base, packages)
    required = required_bumps(packages, base, version_groups(root))
    if not required:
        print(f"No missing breaking bumps since {args.base}.")
        return 0
    for name, (version, reason) in sorted(required.items()):
        print(
            f"{name}: {base[name]} -> {packages[name].version} needs {version}: {reason}"
        )
    if not args.apply:
        print(
            "Run with --apply, or `release-plz set-version` for each crate above.",
            file=sys.stderr,
        )
        return 1
    release_plz = shutil.which("release-plz")
    if release_plz is None:
        print("release-plz is not installed", file=sys.stderr)
        return 1
    subprocess.run(
        [
            release_plz,
            "set-version",
            *(f"{name}@{v}" for name, (v, _) in sorted(required.items())),
        ],
        cwd=root,
        check=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
