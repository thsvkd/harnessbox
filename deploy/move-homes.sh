#!/bin/sh
# Move per-user homes of the single-scope layout (<old>/<user>/.claude/.credentials.json, .claude.json, .codex/auth.json; what
# review-automation's runner kept) into the service layout <new>/<client>/<user>/<harness>/. Copies the credential files only,
# regular files only (never a link), and leaves <old> alone. Run it once as the homes' uid with both volumes mounted:
#   docker run --rm --user 10011:10011 -v runner-homes:/old:ro -v harnessbox-homes:/homes -v "$PWD/deploy:/d:ro" \
#     --entrypoint sh harnessbox:local /d/move-homes.sh /old /homes rva
set -eu
umask 077
old=$1 new=$2 client=$3
copy() { # <from> <to>: a regular file that is not a link
  if [ -f "$1" ] && [ ! -L "$1" ] && [ ! -L "$(dirname "$1")" ]; then mkdir -p -m 700 "$(dirname "$2")"; cp "$1" "$2"; chmod 600 "$2"; echo "  $2"; fi
}
for d in "$old"/*/; do
  d=${d%/}; u=${d##*/}
  case $u in *[!A-Za-z0-9_-]*|'') continue ;; esac
  [ -L "$d" ] && continue
  echo "$u"
  mkdir -p -m 700 "$new/$client/$u"
  copy "$d/.claude/.credentials.json" "$new/$client/$u/claude-code/.claude/.credentials.json"
  [ -f "$new/$client/$u/claude-code/.claude/.credentials.json" ] && copy "$d/.claude.json" "$new/$client/$u/claude-code/.claude.json"
  copy "$d/.codex/auth.json" "$new/$client/$u/codex/.codex/auth.json"
done
