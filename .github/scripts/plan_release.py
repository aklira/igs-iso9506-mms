# SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
# SPDX-License-Identifier: Apache-2.0
"""Check a release tag and select the crates not yet on crates.io.

The crates are published from this repository only, in dependency order. The crates of other repositories that these crates use
(EXTERNAL) must already be on crates.io at the version they are required at, so that a release never publishes a crate whose
dependency is missing.
"""

import json
import os
from pathlib import Path
import tomllib
from urllib.error import HTTPError
from urllib.request import Request, urlopen


CRATES = ("igs-iso9506-mms-codec", "igs-iso9506-mms-link", "igs-iso9506-mms")
EXTERNAL = ()


def published(name, version):
    request = Request(
        f"https://crates.io/api/v1/crates/{name}/{version}",
        headers={"User-Agent": "igs-iso9506-mms-release-workflow"},
    )
    try:
        with urlopen(request, timeout=30) as response:
            entry = json.load(response)["version"]
    except HTTPError as error:
        if error.code == 404:
            return False
        raise
    if entry["num"] != version or entry["yanked"]:
        raise ValueError(f"Unexpected or yanked registry version for {name}")
    return True


def load(path):
    with path.open("rb") as source:
        return tomllib.load(source)


def dependencies(manifest, workspace):
    """The normal dependencies of a manifest, with the `workspace = true` ones resolved from the root manifest."""
    for dependency, spec in manifest.get("dependencies", {}).items():
        if isinstance(spec, str):
            spec = {"version": spec}
        if spec.get("workspace"):
            spec = {**workspace.get(dependency, {}), **{k: v for k, v in spec.items() if k != "workspace"}}
        yield dependency, spec


def release_plan(root, tag, exists=published, external=published):
    workspace = load(root / "Cargo.toml").get("workspace", {}).get("dependencies", {})
    manifests = {}
    for name in CRATES:
        manifest = load(root / "crates" / name / "Cargo.toml")
        package = manifest["package"]
        if package["name"] != name or tag != f"v{package['version']}":
            raise ValueError(f"{name}: tag {tag!r} must match its package version")
        manifests[name] = manifest
    version = manifests[CRATES[0]]["package"]["version"]
    for name, manifest in manifests.items():
        for dependency, spec in dependencies(manifest, workspace):
            if dependency in CRATES and spec.get("version") != version:
                raise ValueError(f"{name}: update the {dependency} version to {version}")
            if dependency in EXTERNAL:
                required = spec.get("version")
                if required is None or not external(dependency, required):
                    raise ValueError(f"{name}: {dependency} {required} must be on crates.io before this release")
    return [name for name in CRATES if not exists(name, version)]


def release_tag(environ):
    """The tag to release: the tag that was pushed, or the tag that a manual run names (workflow_dispatch)."""
    if environ.get("GITHUB_REF_TYPE") == "tag":
        return environ["GITHUB_REF_NAME"]
    if environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and environ.get("RELEASE_TAG"):
        return environ["RELEASE_TAG"]
    raise SystemExit("Publication requires a version tag, or a manual run that names the tag to release")


if __name__ == "__main__":
    pending = release_plan(Path(__file__).resolve().parents[2], release_tag(os.environ))
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        output.write(f"packages={' '.join(pending)}\n")
        output.write(f"publish={str(bool(pending)).lower()}\n")
    print("Pending packages:", ", ".join(pending) or "none (already published)")
