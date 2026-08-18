#!/usr/bin/env bash
set -uo pipefail

SOURCE_DIR="${1:?usage: fic_upload_once.sh SOURCE_DIR}"
FIC_GUARD_LIB="${FIC_GUARD_LIB:-/root/u/deploy/1fichier-upload-guard.sh}"
FIC_UPLOAD_CLI="${FIC_UPLOAD_CLI:-/root/u/fic_upload.py}"
FIC_UPLOAD_STATE="${FIC_UPLOAD_STATE:-/var/lib/fic/fic-upload.db}"
FIC_API_MAX_FILES="${FIC_API_MAX_FILES:-10}"
FIC_API_MAX_BYTES="${FIC_API_MAX_BYTES:-1073741824}"
FIC_API_TIMEOUT_SECONDS="${FIC_API_TIMEOUT_SECONDS:-14400}"

if [[ ! -r "$FIC_GUARD_LIB" || ! -r "$FIC_UPLOAD_CLI" ]]; then
  printf 'SC uploader dependency missing: guard=%s client=%s\n' "$FIC_GUARD_LIB" "$FIC_UPLOAD_CLI" >&2
  exit 75
fi

# shellcheck source=/root/u/deploy/1fichier-upload-guard.sh
source "$FIC_GUARD_LIB"
cleanup() { fic_guard_release 0; }
trap cleanup EXIT INT TERM

guard_rc=0
fic_guard_acquire "sc" || guard_rc=$?
if ((guard_rc != 0)); then
  printf 'SC uploader guard blocked: result=%s wait=%s\n' "${FIC_GUARD_RESULT:-unknown}" "${FIC_GUARD_WAIT_SECONDS:-0}" >&2
  exit "$guard_rc"
fi

upload_rc=0
timeout "${FIC_API_TIMEOUT_SECONDS}s" python3 "$FIC_UPLOAD_CLI" \
  --state "$FIC_UPLOAD_STATE" upload \
  --component sc \
  --remote 1f \
  --destination milo/strip \
  --source "$SOURCE_DIR" \
  --max-files "$FIC_API_MAX_FILES" \
  --max-bytes "$FIC_API_MAX_BYTES" || upload_rc=$?

case "$upload_rc" in
  0) fic_guard_record_status SUCCESS ;;
  76) fic_guard_record_status RATE_LIMIT ;;
  77) fic_guard_record_status AUTH_ERROR ;;
  78) fic_guard_record_status FLOOD_LOCK ;;
  *) FIC_GUARD_RESULT="API_ERROR" ;;
esac
exit "$upload_rc"
