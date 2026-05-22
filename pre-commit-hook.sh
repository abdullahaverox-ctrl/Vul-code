#!/usr/bin/env bash
# AVEROX ASVP — Pre-Commit Security Hook
# Hook type: pre-commit (runs on `git commit`)
# Place at:  .asvp/pre-commit-hook.sh
# Then run:  chmod +x .asvp/pre-commit-hook.sh
#
# Required environment variable on your local machine / CI runner:
#   export ASVP_API_TOKEN="your-asvp-api-token"
#
# Mode: BLOCK (commit stopped on critical findings)

set -euo pipefail

ASVP_URL="https://dev2.averox.com"
# Token is ALWAYS read from the environment — never embedded in this file.
ASVP_TOKEN="${ASVP_API_TOKEN:-}"
WARN_ONLY=0

REPO=$(git remote get-url origin 2>/dev/null || echo "local")
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "pre-commit")

echo "ASVP Security Pre-Commit Hook"
echo "-----------------------------"

# --- preflight: required tools ---------------------------------------------
if ! command -v curl >/dev/null 2>&1; then
  echo "ERROR: 'curl' is required but not installed. Install curl and retry."
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: 'python3' is required for JSON encoding. Install python3 and retry."
  exit 1
fi

# --- preflight: token ------------------------------------------------------
if [ -z "$ASVP_TOKEN" ]; then
  echo "ERROR: ASVP_API_TOKEN is not set."
  echo "Set it with:  export ASVP_API_TOKEN=\"your-asvp-api-token\""
  echo "Then retry the commit."
  exit 1
fi

# Collect staged files we know how to scan
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(js|ts|tsx|jsx|py|java|go|php|cs|rb|tf|yaml|yml|json|dockerfile)$' || true)

if [ -z "$STAGED_FILES" ]; then
  echo "No security-relevant files staged. Skipping scan."
  exit 0
fi

FILE_COUNT=$(echo "$STAGED_FILES" | wc -l | tr -d ' ')
echo "Scanning $FILE_COUNT staged file(s)..."

# Build JSON payload from staged file contents
FILE_JSON="["
FIRST=true
while IFS= read -r file; do
  if [ -f "$file" ]; then
    CONTENT=$(cat "$file" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))" 2>/dev/null || echo '""')
    PATH_JSON=$(printf "%s" "$file" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read().strip()))")
    if [ "$FIRST" = true ]; then FIRST=false; else FILE_JSON+=","; fi
    FILE_JSON+="{\"path\":$PATH_JSON,\"content\":$CONTENT}"
  fi
done <<< "$STAGED_FILES"
FILE_JSON+="]"

REPO_JSON=$(printf "%s" "$REPO" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read().strip()))")
BRANCH_JSON=$(printf "%s" "$BRANCH" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read().strip()))")

# --- call ASVP API ---------------------------------------------------------
# Authorization header is sent via -H, never echoed.
HTTP_CODE=0
RESPONSE=""
set +e
RESPONSE=$(curl -sS --max-time 30 -o /tmp/asvp_pre_commit_resp.json -w "%{http_code}" \
  -X POST "$ASVP_URL/api/devsecops/pre-commit-scan" \
  -H "Authorization: Bearer $ASVP_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"repository\":$REPO_JSON,\"branch\":$BRANCH_JSON,\"commitSha\":\"$COMMIT\",\"files\":$FILE_JSON}")
CURL_EXIT=$?
set -e

if [ $CURL_EXIT -ne 0 ]; then
  echo "WARNING: Could not reach ASVP at $ASVP_URL (network/timeout)."
  echo "Failing OPEN — commit allowed. Re-scan in ASVP after pushing."
  exit 0
fi

HTTP_CODE="$RESPONSE"
BODY=$(cat /tmp/asvp_pre_commit_resp.json 2>/dev/null || echo "")

if [ "$HTTP_CODE" != "200" ]; then
  echo "WARNING: ASVP returned HTTP $HTTP_CODE. Failing OPEN — commit allowed."
  exit 0
fi

# Validate JSON before parsing (handles HTML/error pages safely)
if ! echo "$BODY" | python3 -c "import sys,json; json.load(sys.stdin)" >/dev/null 2>&1; then
  echo "WARNING: ASVP returned a non-JSON response. Failing OPEN — commit allowed."
  exit 0
fi

DECISION=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('decision','passed'))")
CRITICAL=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('criticalCount',0))")
HIGH=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('highCount',0))")

echo ""
if [ "$DECISION" = "passed" ]; then
  echo "PASS — ASVP security gate passed."
  echo "  Critical: $CRITICAL | High: $HIGH"
  exit 0
fi

echo "BLOCKED — ASVP security gate found critical issues."
echo "  Critical: $CRITICAL | High: $HIGH"
echo ""
echo "Top issues:"
echo "$BODY" | python3 -c "
import sys,json
data = json.load(sys.stdin)
for issue in data.get('issues', [])[:5]:
    sev = (issue.get('severity') or '?').upper()
    rule = issue.get('rule') or issue.get('issueType') or '?'
    msg = (issue.get('message') or issue.get('title') or '')[:80]
    fp  = issue.get('filePath') or issue.get('file') or ''
    line = issue.get('lineNumber') or issue.get('line') or ''
    where = f' ({fp}:{line})' if fp else ''
    print(f'  - [{sev}] {rule}: {msg}{where}')
" 2>/dev/null || true

echo ""
echo "Fix the issues above, then commit again."
echo "Details: $ASVP_URL/devsecops-pipeline"

if [ "$WARN_ONLY" = "1" ]; then
  echo ""
  echo "WARN mode is on — commit continues despite findings."
  exit 0
fi

exit 1
