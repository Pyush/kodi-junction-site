#!/usr/bin/env bash
# Secret and dangerous-pattern scan, in the repository so everyone runs the same one.
#
# WHY THIS IS IN THE REPO
#
# It was in ~/.git-hooks, which is git config on one machine (`core.hooksPath`). That meant the check
# protecting every commit was not version-controlled, not reviewed, and did not exist for anyone else
# who cloned the project -- so it gave the illusion of a control rather than being one. CI cannot call a
# file in someone's home directory either, which is why the same check now runs in both places.
#
# Usage:
#   ./scripts/security-check.sh --staged   # only what is about to be committed (pre-commit)
#   ./scripts/security-check.sh --full     # whole tracked tree (CI, pre-push)
#
# Exit 0 = clean. Exit 1 = blocked, with every finding listed rather than just the first.
set -uo pipefail

MODE="${1:---full}"

# Colour only when a human is watching. CI logs are read as plain text, and a wall of escape codes makes
# a failure harder to find rather than easier -- the opposite of the point. The $'' form is also required
# for correctness: with plain quotes the variables hold literal backslash sequences and printf '%s'
# prints them verbatim, which is what the first run of this script did.
if [ -t 2 ]; then
  RED=$'\033[0;31m'; YELLOW=$'\033[1;33m'; GREEN=$'\033[0;32m'; NC=$'\033[0m'
else
  RED=''; YELLOW=''; GREEN=''; NC=''
fi

BLOCKING=0
WARNINGS=0

# --- what counts as a secret ----------------------------------------------------------------
# Credential shapes belonging to a named provider, so a match is actionable rather than a guess. A
# generic "password = something" rule would fire on every seed file, the compose dev credentials and the
# probe scripts, and a check that cries wolf gets switched off.
#
# THESE ARE REGEXES, and are passed to `git grep -E`. A leading `-` would be read as an option, which is
# why every pattern goes in after `-e` below.
SECRET_PATTERNS=(
  'sk_live_'
  'AKIA[0-9A-Z]{16}'
  'AIzaSy[a-zA-Z0-9_-]{33}'
  'ghp_[a-zA-Z0-9]{36}'
  'github_pat_[a-zA-Z0-9_]{22}'
  'mongodb\+srv://[^"'"'"']*:[^"'"'"']*@'
  '\-\-\-\-\-BEGIN RSA PRIVATE KEY\-\-\-\-\-'
  '\-\-\-\-\-BEGIN (EC |OPENSSH )?PRIVATE KEY\-\-\-\-\-'
  'sk-proj-'
  'EAA[a-zA-Z0-9]{100,}'
  'whsec_[a-zA-Z0-9]{60,}'
  'rzp_live_'
  'xox[baprs]-[a-zA-Z0-9-]{10,}'                            # Slack
  'SG\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}'              # SendGrid
)

# Values that look like a secret but are documentation. One expression, so adding a case is one line and
# the exclusions stay visible in the same place as the patterns they excuse.
NOT_A_SECRET='example|dummy|placeholder|fake|test_123|REPLACE_ME|changeme|CHANG3Me|\.\.\.|xxxxx|AgBx\.\.\.'

# --- what counts as dangerous ---------------------------------------------------------------
# LITERAL strings, not regexes: `eval(` is an unmatched group paren in ERE, so the first version of this
# script passed them to `git grep -E` and git grep errored out. Fixed strings also avoid inventing a
# metacharacter story for code that has none.
#
# Only warnings. These are not errors in a codebase that legitimately forks a database container, and
# blocking on them trains people to reach for --no-verify.
DANGEROUS_LITERAL=(
  'new Function('
  'eval('
  'execSync('
  'Runtime.getRuntime().exec('
  'ProcessBuilder('
  'ObjectInputStream'
  'setAccessible(true)'
)

# This file is excluded from its own scan, and that needs saying out loud.
#
# It necessarily contains every pattern it looks for -- `sk_live_` is in the array below -- so it matches
# itself and every run blocks. Splitting each pattern into adjacent quoted fragments would fix it and
# would also make this file unreadable, and readability is the point for a control somebody has to audit
# and extend. The cost is small and bounded: a credential pasted into THIS file would not be caught,
# which is also where credentials are least likely to end up, since it holds no user data.
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
SELF_REL="${SELF#"$PWD"/}"

# --- reporting ------------------------------------------------------------------------------
#
# SECURITY_CHECK_EXTRA_PATTERNS points at a file of one-regex-per-line, appended to the credential list.
# It exists so the negative tests can inject a pattern that git grep cannot compile. That case is the
# important one to cover: the script must report a scan failure as a FAILURE rather than as a clean tree,
# and a test that cannot inject a broken pattern cannot prove it.
if [ -n "${SECURITY_CHECK_EXTRA_PATTERNS:-}" ] && [ -f "${SECURITY_CHECK_EXTRA_PATTERNS}" ]; then
  while IFS= read -r line; do
    [ -n "$line" ] && SECRET_PATTERNS+=("$line")
  done < "${SECURITY_CHECK_EXTRA_PATTERNS}"
fi
report() {
  local severity="$1" description="$2" matches="$3"
  if [ "$severity" = "block" ]; then
    printf '%s\n' "${RED}BLOCKED  $description${NC}" >&2
    BLOCKING=$((BLOCKING + 1))
  else
    printf '%s\n' "${YELLOW}WARNING  $description${NC}" >&2
    WARNINGS=$((WARNINGS + 1))
  fi
  printf '%s\n' "$matches" | head -5 >&2
  echo >&2
}

# run_grep <git-grep-args...> -- writes matches to $GREP_FILE, sets $GREP_STATUS.
#
# NOT a function that prints its result. The version that did `out="$(git grep ...)"` and then
# incremented BLOCKING on an error path incremented it INSIDE a command substitution -- a subshell -- so
# the counter never reached the parent and a scan failure was printed and then ignored. It reported
# "SCAN ERROR" and then finished with "OK" and exit 0: failing open while telling you it had not.
# Writing to a file and setting a variable keeps both in this shell.
GREP_FILE="$(mktemp)"
GREP_ERR="$(mktemp)"
trap 'rm -f "$GREP_FILE" "$GREP_ERR"' EXIT
GREP_STATUS=0

run_grep() {
  : > "$GREP_FILE"
  : > "$GREP_ERR"
  git grep "$@" > "$GREP_FILE" 2> "$GREP_ERR"
  # 0 = matched, 1 = no match (the good case), >=2 = the scan itself failed.
  GREP_STATUS=$?
}

report_scan_error() {
  local pattern="$1"
  printf '%s\n' "${RED}SCAN ERROR  git grep exited $GREP_STATUS on pattern '${pattern}' -- a scan that did not run is not a clean result${NC}" >&2
  head -3 "$GREP_ERR" | note_indent >&2
  BLOCKING=$((BLOCKING + 1))
}

note_indent() { sed 's/^/    /'; }

filter() { grep -Ev "$NOT_A_SECRET" "$GREP_FILE" || true; }

# staged_matches <-E|-F> <pattern> -- same contract, over the staged diff.
#
# The pathspec excludes this file for the same reason run_grep does: a staged change to the scanner
# would otherwise match its own pattern list.
staged_matches() {
  : > "$GREP_FILE"
  : > "$GREP_ERR"
  local added
  added="$(git diff --cached --diff-filter=ACM -- . ":(exclude)$SELF_REL" | grep '^+' || true)"
  if [ "$1" = "-E" ]; then
    printf '%s' "$added" | grep -E -e "$2" > "$GREP_FILE" 2> "$GREP_ERR"
  else
    printf '%s' "$added" | grep -F -e "$2" > "$GREP_FILE" 2> "$GREP_ERR"
  fi
  GREP_STATUS=$?
}

case "$MODE" in
  --staged) echo "security check: staged changes" >&2 ;;
  --full)   echo "security check: whole tracked tree" >&2 ;;
  *)        echo "usage: $0 [--staged|--full]" >&2; exit 2 ;;
esac
echo >&2

# --- credential patterns --------------------------------------------------------------------
for pattern in "${SECRET_PATTERNS[@]}"; do
  if [ "$MODE" = "--staged" ]; then
    staged_matches -E "$pattern"
  else
    run_grep -nI -E -e "$pattern" -- . ":(exclude)$SELF_REL"
  fi
  [ "$GREP_STATUS" -ge 2 ] && { report_scan_error "$pattern"; continue; }
  hits="$(filter)"
  [ -n "$hits" ] && report block "credential matching '${pattern}'" "$hits"
done

# --- dangerous literals ---------------------------------------------------------------------
for pattern in "${DANGEROUS_LITERAL[@]}"; do
  if [ "$MODE" = "--staged" ]; then
    staged_matches -F "$pattern"
  else
    run_grep -nI -F -e "$pattern" -- . ":(exclude)$SELF_REL"
  fi
  [ "$GREP_STATUS" -ge 2 ] && { report_scan_error "$pattern"; continue; }
  hits="$(cat "$GREP_FILE")"
  [ -n "$hits" ] && report warn "dangerous literal '${pattern}' - review deliberately" "$hits"
done

# --- repository-specific: no Secret document may reach the repository ------------------------
# The manifests deliberately ship a Secret TEMPLATE, and validate-manifests.py already refuses any
# Secret in a rendered overlay. This catches one at authoring time, in the file.
#
# Matches on `kind: Secret`, NOT on `data:` -- every ConfigMap has a `data:` key, so the first version
# of this check flagged all three overlay ConfigMap patches as committed Secrets, which is precisely the
# crying wolf that gets a check disabled.
if [ "$MODE" = "--full" ]; then
  while IFS= read -r f; do
    case "$f" in *02-secret.example.yaml) continue ;;   # the template, all REPLACE_ME
    esac
    if grep -qE '^kind:[[:space:]]*Secret[[:space:]]*$' "$f" 2>/dev/null; then
      printf '%s\n' "${RED}BLOCKED  $f is a Secret document${NC}" >&2
      printf '  Secrets belong out of band -- see base/02-secret.example.yaml. A committed Secret is a\n' >&2
      printf '  committed credential even when every value looks like a placeholder.\n\n' >&2
      BLOCKING=$((BLOCKING + 1))
    fi
  done < <(git ls-files 'infrastructure/kubernetes/*.yaml' 'infrastructure/kubernetes/**/*.yaml')
fi

echo >&2
if [ "$BLOCKING" -gt 0 ]; then
  printf '%s\n' "${RED}BLOCKED - $BLOCKING blocking issue(s).${NC}" >&2
  exit 1
fi
if [ "$WARNINGS" -gt 0 ]; then
  printf '%s\n' "${YELLOW}passed with $WARNINGS warning(s) - none blocking.${NC}" >&2
  exit 0
fi
printf '%s\n' "${GREEN}OK - no secrets or dangerous patterns found.${NC}" >&2
exit 0