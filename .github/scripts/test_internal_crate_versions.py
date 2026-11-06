import contextlib
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import internal_crate_versions as icv


def write_workspace(
    root: Path, versions: dict[str, str], requirement_precision: str = "full"
) -> None:
    """A workspace shaped like ours: core <- api <- sdk, core <- lite <- cli (one version group)."""
    crates = {
        "core": {"deps": [], "bin": False, "publish": True},
        "api": {"deps": ["core"], "bin": False, "publish": True},
        "sdk": {"deps": ["api"], "bin": False, "publish": True},
        "lite": {"deps": ["core"], "bin": False, "publish": True},
        "cli": {"deps": ["lite"], "bin": True, "publish": True},
        "internal": {"deps": ["core"], "bin": False, "publish": False},
        "other": {"deps": [], "bin": False, "publish": True},
    }

    def requirement(name: str) -> str:
        version = versions[name]
        return version if requirement_precision == "full" else version.rsplit(".", 1)[0]

    workspace_deps = "\n".join(
        f'{name} = {{ path = "{name}", version = "{requirement(name)}" }}'
        for name in crates
    )
    (root / "Cargo.toml").write_text(
        f'[workspace]\nresolver = "2"\nmembers = {sorted(crates)!r}\n\n[workspace.dependencies]\n{workspace_deps}\n'.replace(
            "'", '"'
        )
    )
    (root / "release-plz.toml").write_text(
        '[[package]]\nname = "lite"\nversion_group = "g"\n\n[[package]]\nname = "cli"\nversion_group = "g"\n'
    )
    for name, spec in crates.items():
        (root / name / "src").mkdir(parents=True, exist_ok=True)
        deps = "\n".join(f"{dep} = {{ workspace = true }}" for dep in spec["deps"])
        publish = "" if spec["publish"] else "publish = false\n"
        (root / name / "Cargo.toml").write_text(
            f'[package]\nname = "{name}"\nversion = "{versions[name]}"\nedition = "2021"\n{publish}\n[dependencies]\n{deps}\n'
        )
        source = "main.rs" if spec["bin"] else "lib.rs"
        (root / name / "src" / source).write_text(
            "fn main() {}\n" if spec["bin"] else ""
        )


def git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
        cwd=root,
        check=True,
        capture_output=True,
    )


def run(argv: list[str]) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = icv.main(argv)
    return code, out.getvalue()


class InternalCrateVersionsTest(unittest.TestCase):
    def test_breaking_bump_propagates_to_dependent_libraries_and_version_groups(
        self,
    ) -> None:
        released = {
            "core": "0.4.0",
            "api": "0.2.0",
            "sdk": "0.7.0",
            "lite": "0.9.0",
            "cli": "0.9.0",
            "internal": "0.1.0",
            "other": "0.1.0",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_workspace(root, released)
            git(root, "init", "-q")
            git(root, "add", "-A")
            git(root, "commit", "-qm", "released")

            # What release-plz proposes: a breaking core, and patch releases for its dependents.
            write_workspace(
                root,
                released
                | {
                    "core": "0.5.0",
                    "api": "0.2.1",
                    "sdk": "0.7.1",
                    "lite": "0.9.1",
                    "cli": "0.9.1",
                },
            )

            code, output = run(["--root", tmp, "breaking-bumps", "--base", "HEAD"])
            self.assertEqual(code, 1, output)

            bin_dir = root / "bin"
            bin_dir.mkdir()
            record = root / "release-plz-args"
            stub = bin_dir / "release-plz"
            stub.write_text(f'#!/bin/sh\necho "$@" > "{record}"\n')
            stub.chmod(0o755)
            with mock.patch.dict(
                os.environ, {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}
            ):
                code, output = run(
                    ["--root", tmp, "breaking-bumps", "--base", "HEAD", "--apply"]
                )
            self.assertEqual(code, 0, output)
            # sdk only depends on core through api, cli only through its version group with lite.
            # internal is unpublished and other doesn't depend on core, so they're left alone.
            self.assertEqual(
                record.read_text().split(),
                ["set-version", "api@0.3.0", "cli@0.10.0", "lite@0.10.0", "sdk@0.8.0"],
            )

    def test_requirements_must_match_current_versions(self) -> None:
        versions = {
            name: "0.3.2"
            for name in ("core", "api", "sdk", "lite", "cli", "internal", "other")
        }
        with tempfile.TemporaryDirectory() as tmp:
            write_workspace(Path(tmp), versions, requirement_precision="minor")
            code, output = run(["--root", tmp, "check-requirements"])
            self.assertEqual(code, 1, output)
            self.assertIn("version = '0.3', expected '0.3.2'", output)

            write_workspace(Path(tmp), versions)
            code, output = run(["--root", tmp, "check-requirements"])
            self.assertEqual(code, 0, output)


if __name__ == "__main__":
    unittest.main()
