#!/bin/sh
# When run as a GitHub Action, inputs are passed as INPUT_* env vars.
# Otherwise pass args through to fors33-verifier (e.g. docker run image --url ... --expected-hash ...).
set -e

if [ -n "$INPUT_URL" ] || [ -n "$INPUT_FILE" ] || [ -n "$INPUT_MODE" ] || [ -n "$INPUT_ROOT" ] || [ -n "$INPUT_RECORD" ]; then
    # GitHub Action mode: build args from env. File/URL hash mode stays the default when mode/root unset.
    set --
    [ -n "$INPUT_MODE" ]         && set -- "$@" --mode "$INPUT_MODE"
    [ -n "$INPUT_ROOT" ]         && set -- "$@" --root "$INPUT_ROOT"
    [ -n "$INPUT_URL" ]          && set -- "$@" --url "$INPUT_URL"
    [ -n "$INPUT_FILE" ]         && set -- "$@" --file "$INPUT_FILE"
    [ -n "$INPUT_EXPECTED_HASH" ] && set -- "$@" --expected-hash "$INPUT_EXPECTED_HASH"
    [ -n "$INPUT_RECORD" ]       && set -- "$@" --record "$INPUT_RECORD"
    [ -n "$INPUT_START" ]        && set -- "$@" --start "$INPUT_START"
    [ -n "$INPUT_END" ]          && set -- "$@" --end "$INPUT_END"
    exec fors33-verifier "$@"
fi

# If first arg is "serve" or "server", run URL-only API (no file uploads).
case "$1" in
  serve|server) exec python /app/server_url_only.py ;;
  *)            exec fors33-verifier "$@" ;;
esac
