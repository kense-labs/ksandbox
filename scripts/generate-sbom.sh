#!/usr/bin/env bash
# Generate a CycloneDX 1.5 JSON SBOM from `cargo metadata` (no extra crates).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="${1:-sbom.cdx.json}"
META="$(mktemp)"
trap 'rm -f "$META"' EXIT
cargo metadata --format-version 1 --manifest-path Cargo.toml >"$META"
python3 - "$META" "$OUT" <<'PY'
import json, sys, os, datetime, hashlib, uuid

meta_path, out_path = sys.argv[1], sys.argv[2]
meta = json.load(open(meta_path))
resolve = {p["id"]: p for p in meta["packages"]}

# The crate lives in a shared workspace: the SBOM root is the package whose
# manifest is this crate's own Cargo.toml, and components are its reachable
# dependency graph, not every workspace member.
crate_dir = os.getcwd()
root_pkg = next(p for p in meta["packages"] if os.path.dirname(p["manifest_path"]) == crate_dir)
root_id = root_pkg["id"]

nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
reachable = set()
stack = [root_id]
while stack:
    pid = stack.pop()
    if pid in reachable:
        continue
    reachable.add(pid)
    node = nodes.get(pid)
    if node:
        stack.extend(d["pkg"] for d in node["deps"])

components = []
for pkg_id in sorted(reachable):
    pkg = resolve[pkg_id]
    purl = f"pkg:cargo/{pkg['name']}@{pkg['version']}"
    components.append({
        "type": "library",
        "bom-ref": pkg_id,
        "name": pkg["name"],
        "version": pkg["version"],
        "purl": purl,
        "scope": "required",
    })

bom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": f"urn:uuid:{uuid.uuid4()}",
    "version": 1,
    "metadata": {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tools": {"components": [{"type": "application", "name": root_pkg["name"] + "-sbom", "version": "0.1.3"}]},
        "component": {
            "type": "library",
            "name": root_pkg["name"],
            "version": root_pkg["version"],
            "purl": f"pkg:cargo/{root_pkg['name']}",
        },
    },
    "components": components,
}

raw = json.dumps(bom, indent=2, sort_keys=True) + "\n"
open(out_path, "w").write(raw)
digest = hashlib.sha256(raw.encode()).hexdigest()
print(f"wrote {out_path} components={len(components)} sha256={digest}")
PY
