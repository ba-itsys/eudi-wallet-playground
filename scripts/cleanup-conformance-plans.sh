#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

if [ -f "$ROOT_DIR/.env" ]; then
  # shellcheck disable=SC1091
  set -a
  . "$ROOT_DIR/.env"
  set +a
fi

usage() {
  cat <<'EOF'
Usage: scripts/cleanup-conformance-plans.sh [options]

Deletes OIDF conformance test plans where all test instances are finished/interrupted.

Defaults:
  - Uses .env (repo root) for VERIFIER_CONFORMANCE_BASE_URL and VERIFIER_CONFORMANCE_API_KEY
  - Dry-run (shows what would be deleted)

Options:
  --base-url <url>      Conformance suite base URL (e.g. https://demo.certification.openid.net)
  --api-key <token>     Conformance API key/token (Bearer)
  --include-non-terminal Also delete plans with non-terminal test instances (RUNNING/CREATED/etc)
  --include-empty       Also delete plans with zero test instances
  --yes                 Delete without prompting (otherwise asks)
  --dry-run             Never delete, only print candidates (default)
  -h, --help            Show this help

Examples:
  scripts/cleanup-conformance-plans.sh
  scripts/cleanup-conformance-plans.sh --include-non-terminal --yes
  scripts/cleanup-conformance-plans.sh --include-empty
  scripts/cleanup-conformance-plans.sh --yes
EOF
}

normalize_base_url() {
  base="$(printf '%s' "${1:-}" | tr -d '\r\n')"
  while [ -n "$base" ] && [ "${base%/}" != "$base" ]; do
    base="${base%/}"
  done
  if [ "${base%/api}" != "$base" ]; then
    base="${base%/api}"
  fi
  printf '%s' "$base"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

is_terminal_status() {
  case "${1:-}" in
    FINISHED|INTERRUPTED) return 0 ;;
    *) return 1 ;;
  esac
}

BASE_URL="${VERIFIER_CONFORMANCE_BASE_URL:-${OIDF_CONFORMANCE_BASE_URL:-https://demo.certification.openid.net}}"
API_KEY="${VERIFIER_CONFORMANCE_API_KEY:-${OIDF_CONFORMANCE_API_KEY:-}}"
INCLUDE_EMPTY=0
INCLUDE_NON_TERMINAL=0
DRY_RUN=1
YES=0

while [ $# -gt 0 ]; do
  case "$1" in
    --base-url)
      BASE_URL="${2:-}"
      shift 2
      ;;
    --api-key)
      API_KEY="${2:-}"
      shift 2
      ;;
    --include-empty)
      INCLUDE_EMPTY=1
      shift
      ;;
    --include-non-terminal)
      INCLUDE_NON_TERMINAL=1
      shift
      ;;
    --yes)
      YES=1
      DRY_RUN=0
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_cmd curl
require_cmd jq

BASE_URL="$(normalize_base_url "$BASE_URL")"
if [ -z "$BASE_URL" ]; then
  echo "Missing base URL. Set VERIFIER_CONFORMANCE_BASE_URL in .env or pass --base-url." >&2
  exit 1
fi
if [ -z "${API_KEY:-}" ]; then
  echo "Missing API key. Set VERIFIER_CONFORMANCE_API_KEY in .env or pass --api-key." >&2
  exit 1
fi

page_size=50
start=0
total=1

plans_tmp="$(mktemp -t conformance-plans.XXXXXX.jsonl)"
candidates_tmp="$(mktemp -t conformance-plans-candidates.XXXXXX.jsonl)"

cleanup() {
  rm -f "$plans_tmp" "$candidates_tmp" >/dev/null 2>&1 || true
}
trap cleanup INT TERM EXIT

fetch_page() {
  curl -fsS \
    -H "Authorization: Bearer $API_KEY" \
    -H "Accept: application/json" \
    "$BASE_URL/api/plan?draw=1&start=$start&length=$page_size"
}

fetch_info_status() {
  test_id="$1"
  curl -fsS \
    -H "Authorization: Bearer $API_KEY" \
    -H "Accept: application/json" \
    "$BASE_URL/api/info/$test_id" \
    | jq -r '.status // ""'
}

echo "Listing conformance plans from: $BASE_URL"

while [ "$start" -lt "$total" ]; do
  page="$(fetch_page)"
  total="$(printf '%s' "$page" | jq -r '.recordsTotal // 0')"
  printf '%s' "$page" | jq -c '.data[]' >>"$plans_tmp"
  start=$((start + page_size))
done

plan_count="$(wc -l <"$plans_tmp" | tr -d ' ')"
if [ "$INCLUDE_NON_TERMINAL" -eq 1 ]; then
  echo "Found $plan_count plan(s). Selecting plans including non-terminal instances..."
else
  echo "Found $plan_count plan(s). Checking instance status..."
fi

while IFS= read -r plan; do
  plan_id="$(printf '%s' "$plan" | jq -r '._id // .id // ""')"
  plan_name="$(printf '%s' "$plan" | jq -r '.planName // ""')"
  alias="$(printf '%s' "$plan" | jq -r '.config.alias // ""')"
  publish="$(printf '%s' "$plan" | jq -r '.publish // ""')"

  instance_ids="$(printf '%s' "$plan" | jq -r '.modules[].instances[]? // empty')"
  if [ -z "$instance_ids" ]; then
    if [ "$INCLUDE_EMPTY" -eq 1 ]; then
      printf '%s\n' "$plan" >>"$candidates_tmp"
    fi
    continue
  fi

  if [ "$INCLUDE_NON_TERMINAL" -eq 1 ]; then
    printf '%s\n' "$plan" >>"$candidates_tmp"
    continue
  fi

  all_terminal=1
  for test_id in $instance_ids; do
    status=""
    if status="$(fetch_info_status "$test_id" 2>/dev/null)"; then
      :
    else
      status=""
    fi
    if ! is_terminal_status "$status"; then
      all_terminal=0
      break
    fi
  done

  if [ "$all_terminal" -eq 1 ]; then
    printf '%s\n' "$plan" >>"$candidates_tmp"
  fi
done <"$plans_tmp"

candidate_count="$(wc -l <"$candidates_tmp" | tr -d ' ')"
if [ "$candidate_count" -eq 0 ]; then
  if [ "$INCLUDE_NON_TERMINAL" -eq 1 ]; then
    echo "No plans to delete."
  else
    echo "No finished plans to delete."
  fi
  exit 0
fi

echo ""
echo "Plans eligible for deletion ($candidate_count):"
nl -ba "$candidates_tmp" \
  | while IFS= read -r line; do
      idx="$(printf '%s' "$line" | cut -f1)"
      json="$(printf '%s' "$line" | cut -f2-)"
      id="$(printf '%s' "$json" | jq -r '._id // .id // ""')"
      name="$(printf '%s' "$json" | jq -r '.planName // ""')"
      alias="$(printf '%s' "$json" | jq -r '.config.alias // ""')"
      publish="$(printf '%s' "$json" | jq -r '.publish // ""')"
      printf '%s) %s | %s | alias=%s | publish=%s\n' "$idx" "$id" "$name" "$alias" "$publish"
    done

if [ "$DRY_RUN" -eq 1 ]; then
  echo ""
  echo "Dry-run only. Re-run with --yes to delete."
  exit 0
fi

if [ "$YES" -ne 1 ]; then
  echo ""
  printf "Delete %s plan(s)? [y/N] " "$candidate_count"
  read -r answer || true
  case "${answer:-}" in
    y|Y|yes|YES) ;;
    *)
      echo "Aborted."
      exit 0
      ;;
  esac
fi

deleted=0
failed=0
while IFS= read -r plan; do
  plan_id="$(printf '%s' "$plan" | jq -r '._id // .id // ""')"
  if [ -z "$plan_id" ]; then
    continue
  fi

  http_code="$(curl -sS -o /tmp/conformance-plan-delete.$$ -w '%{http_code}' \
    -X DELETE \
    -H "Authorization: Bearer $API_KEY" \
    -H "Accept: application/json" \
    "$BASE_URL/api/plan/$plan_id" || true)"

  if [ "${http_code#2}" != "$http_code" ]; then
    deleted=$((deleted + 1))
    echo "Deleted plan: $plan_id"
  else
    failed=$((failed + 1))
    echo "Failed to delete plan: $plan_id (HTTP $http_code)" >&2
    if [ -s /tmp/conformance-plan-delete.$$ ]; then
      head -c 400 /tmp/conformance-plan-delete.$$ >&2 || true
      echo "" >&2
    fi
  fi
done <"$candidates_tmp"

rm -f /tmp/conformance-plan-delete.$$ >/dev/null 2>&1 || true

echo ""
echo "Done. Deleted=$deleted Failed=$failed"
