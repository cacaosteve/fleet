#!/bin/bash
# Updates dogfood + standard-library macOS OS-currency policies from Apple's
# GDMF feed (https://gdmf.apple.com/v2/pmv), applying the same grace-day floors
# as server/mdm/apple/gdmf.RequiredMacOSVersions.
#
# Policies:
#   - up to date:      grace_days = 0
#   - acceptable:      grace_days = 30

set -euo pipefail

DOGFOOD_UP_TO_DATE="it-and-security/lib/macos/policies/latest-macos.yml"
DOGFOOD_ACCEPTABLE="it-and-security/lib/macos/policies/acceptable-macos.yml"
STANDARD_LIBRARY="docs/01-Using-Fleet/standard-query-library/standard-query-library.yml"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required."
    exit 1
fi

TMP_GDMF="$(mktemp)"
trap 'rm -f "$TMP_GDMF"' EXIT

echo "Fetching macOS versions from Apple GDMF..."
curl -fsSL "https://gdmf.apple.com/v2/pmv" > "$TMP_GDMF"

# Compute dual-major floors for grace 0 and 30. Prints shell assignments:
#   UP_TO_DATE_QUERY='...'
#   ACCEPTABLE_QUERY='...'
#   LATEST_FLOORS='...'
#   ACCEPTABLE_FLOORS='...'
eval "$(GDMF_PATH="$TMP_GDMF" python3 <<'PY'
import json, os, shlex
from datetime import datetime, timezone

path = os.environ["GDMF_PATH"]
raw = open(path, encoding="utf-8").read()
if raw.startswith("ey"):
    import base64
    payload = raw.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    meta = json.loads(base64.urlsafe_b64decode(payload))
else:
    meta = json.loads(raw)

assets = meta.get("AssetSets", {}).get("macOS") or meta.get("PublicAssetSets", {}).get("macOS") or []
if not assets:
    raise SystemExit("Error: no macOS assets in GDMF response")

def parse_date(s):
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None

def version_key(v):
    parts = []
    for p in v.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    return parts

by_major = {}
for a in assets:
    v = a.get("ProductVersion") or ""
    if not v:
        continue
    try:
        major = int(v.split(".")[0])
    except ValueError:
        continue
    by_major.setdefault(major, []).append(a)

majors = sorted(by_major.keys(), reverse=True)[:2]
now = datetime.now(timezone.utc)

def floors_with_major(grace_days):
    out = []
    for major in majors:
        best = {}
        for a in by_major[major]:
            v = a["ProductVersion"]
            posted = parse_date(a.get("PostingDate"))
            prev = best.get(v)
            if prev is None:
                best[v] = (v, posted)
                continue
            _, prev_posted = prev
            if prev_posted is None and posted is not None:
                best[v] = (v, posted)
            elif prev_posted is not None and posted is not None and posted < prev_posted:
                best[v] = (v, posted)
        ordered = sorted(best.values(), key=lambda r: version_key(r[0]), reverse=True)
        if not ordered:
            continue
        latest_v, latest_posted = ordered[0]
        required = latest_v
        if grace_days > 0 and len(ordered) > 1 and latest_posted is not None:
            age = now - latest_posted
            if age.total_seconds() < grace_days * 24 * 3600:
                required = ordered[1][0]
        out.append((major, required))
    return out

def query(floors_list):
    # floors_list is [(major, version), ...]
    if not floors_list:
        return ""
    clauses = " OR ".join(
        f"(major = {major} AND version_compare(version, '{version}') >= 0)"
        for major, version in floors_list
    )
    return f"SELECT 1 FROM os_version WHERE {clauses};"

up = floors_with_major(0)
acc = floors_with_major(30)
print("UP_TO_DATE_QUERY=" + shlex.quote(query(up)))
print("ACCEPTABLE_QUERY=" + shlex.quote(query(acc)))
print("LATEST_FLOORS=" + shlex.quote(",".join(v for _, v in up)))
print("ACCEPTABLE_FLOORS=" + shlex.quote(",".join(v for _, v in acc)))
PY
)"

if [ -z "${UP_TO_DATE_QUERY:-}" ] || [ -z "${ACCEPTABLE_QUERY:-}" ]; then
    echo "Error: failed to compute version floors from GDMF."
    exit 1
fi

echo "Up-to-date floors: ${LATEST_FLOORS}"
echo "Acceptable floors: ${ACCEPTABLE_FLOORS}"

write_dogfood_policy() {
    local path="$1"
    local name="$2"
    local query="$3"
    local critical="$4"
    local fleet_managed_key="$5"
    local description="$6"
    cat > "$path" <<EOF
- name: ${name}
  query: ${query}
  critical: ${critical}
  fleet_managed_key: ${fleet_managed_key}
  description: ${description}
  resolution: Please find time to run Software Update.  > System Settings > Software Update
  platform: darwin
  calendar_events_enabled: false
EOF
}

mkdir -p "$(dirname "$DOGFOOD_UP_TO_DATE")"

write_dogfood_policy "$DOGFOOD_UP_TO_DATE" \
    "macOS - Operating system up to date" \
    "$UP_TO_DATE_QUERY" \
    "true" \
    "macos_os_up_to_date" \
    "Using an outdated macOS version risks exposure to security vulnerabilities and potential system instability. Fleet keeps these version floors current from Apple's GDMF catalog (grace_days = 0)."

write_dogfood_policy "$DOGFOOD_ACCEPTABLE" \
    "macOS - Operating system version is acceptable" \
    "$ACCEPTABLE_QUERY" \
    "false" \
    "macos_os_acceptable" \
    "Hosts may trail the latest macOS point release for up to 30 days after Apple publishes it. Fleet keeps these version floors current from Apple's GDMF catalog (grace_days = 30)."

# Update standard-query-library in place (name-keyed).
if [ -f "$STANDARD_LIBRARY" ]; then
    python3 - "$STANDARD_LIBRARY" "$UP_TO_DATE_QUERY" "$ACCEPTABLE_QUERY" <<'PY'
import re, sys
path, up_q, acc_q = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, encoding="utf-8").read()
failed = []

def replace_policy_query(text, name, query):
    pattern = re.compile(
        rf"(name:\s*{re.escape(name)}\n(?:.*\n)*?  query:\s*)(.*)",
        re.MULTILINE,
    )
    new_text, n = pattern.subn(rf"\g<1>{query}", text, count=1)
    if n != 1:
        failed.append(name)
        return text
    return new_text

text = replace_policy_query(text, "Operating system up to date (macOS)", up_q)
text = replace_policy_query(text, "Operating system version is acceptable (macOS)", acc_q)
if failed:
    print(f"Error: could not update query for {failed!r} in {path}", file=sys.stderr)
    sys.exit(1)
open(path, "w", encoding="utf-8").write(text)
print(f"Updated {path}")
PY
fi

if git diff --quiet -- "$DOGFOOD_UP_TO_DATE" "$DOGFOOD_ACCEPTABLE" "$STANDARD_LIBRARY" 2>/dev/null; then
    echo "No updates needed; macOS OS-currency policies are current."
else
    echo "Files updated successfully. PR will be created by GitHub Actions workflow."
    git diff -- "$DOGFOOD_UP_TO_DATE" "$DOGFOOD_ACCEPTABLE" "$STANDARD_LIBRARY" || true
fi
