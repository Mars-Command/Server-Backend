import hashlib, json, os, sqlite3, sys
from pathlib import Path

env = {}
for line in Path(".env").read_text().splitlines():
    if "=" in line and not line.lstrip().startswith("#"):
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip().strip('"').strip("'")
get = lambda k, d=None: os.environ.get(k) or env.get(k) or d
legacy = Path(get("MARS_RELEASE_DIR", "/opt/mars-package-api/releases/1.0.0")).resolve()
pub = Path(
    get("MARS_RELEASE_PUBLISH_DIR", str(legacy.parent / f".{legacy.name}-publisher"))
)
dirs = [
    d.strip()
    for d in get(
        "MARS_MANAGED_DIRS",
        "mods,config,defaultconfigs,kubejs,resourcepacks,shaderpacks",
    ).split(",")
    if d.strip()
]
db = sqlite3.connect(pub / "state.sqlite3")
row = db.execute(
    "SELECT deployment_id FROM active_release WHERE singleton=1"
).fetchone()
print("publisher dir:", pub)
for r in db.execute("SELECT id, status, base_id FROM deployments"):
    m = db.execute("SELECT manifest FROM deployments WHERE id=?", (r[0],)).fetchone()[0]
    print(
        f"  deployment {r[0][:12]} status={r[1]} pack={json.loads(m)['packVersion']} base={str(r[2])[:12]}"
    )
if not row:
    sys.exit("no active_release -> legacy mode")
aid = row[0]
root = pub / "published" / aid / "release"
dbman, dbsig = db.execute(
    "SELECT manifest, signature FROM deployments WHERE id=?", (aid,)
).fetchone()
disk = (root / "manifest.json").read_bytes()
print("active:", aid, "pack", json.loads(dbman)["packVersion"])
print(
    "on-disk manifest matches DB copy:",
    disk == dbman,
    "| sig matches:",
    (root / "manifest.json.sig").read_text().strip() == dbsig,
)
signed = {f["path"]: (f["sha256"], f["size"]) for f in json.loads(disk)["files"]}
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
actual = {}
for d in dirs:
    base = root / d
    if not base.is_dir():
        continue
    for cur, subs, names in os.walk(base):
        subs[:] = [s for s in subs if not (Path(cur) / s).is_symlink()]
        for n in names:
            p = Path(cur) / n
            if p.is_file() and not p.is_symlink():
                actual[p.relative_to(root).as_posix()] = (sha(p), p.stat().st_size)
missing = sorted(set(signed) - set(actual))
extra = sorted(set(actual) - set(signed))
changed = sorted(k for k in set(signed) & set(actual) if signed[k] != actual[k])
print(
    f"signed={len(signed)} on_disk={len(actual)} missing={len(missing)} extra={len(extra)} changed={len(changed)}"
)
for label, items in (("MISSING", missing), ("EXTRA", extra), ("CHANGED", changed)):
    for i in items[:40]:
        print(f"  {label} {i}")
