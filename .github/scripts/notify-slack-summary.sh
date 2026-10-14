#!/usr/bin/env bash
#
# Build the Slack deploy-summary payload from this run's jobs and write it to
# $GITHUB_OUTPUT (headline_text, headline_blocks, detail_blocks) for
# notify-slack.yml to post.
#
# Env (set by the workflow's `env:` block): GH_TOKEN GH_REPO RUN_ID ACTOR
# PIPELINE RUN_URL SLACK_USER_MAP, and TAG RELEASE_NAME RELEASE_URL
# RELEASE_AUTHOR (empty on workflow_dispatch).
#
# pipefail matters: a failed `gh_api_retry | jq -s` must fail the step, not
# yield JOBS=[] and a green job — the silent failure this notifier prevents.
set -eo pipefail

# stderr to a file, not 2>&1: a gh warning mixed into stdout would make `jq -s`
# choke on non-JSON. Surfaced only in the failure diagnostic.
ERR_FILE="${RUNNER_TEMP:-/tmp}/gh_api_err"
gh_api_retry() {
  for i in 1 2 3; do
    if OUT=$(gh api "$1" --paginate --jq "$2" 2>"$ERR_FILE"); then
      echo "$OUT"
      return 0
    fi
    [ "$i" -lt 3 ] && echo "gh api $1 failed (attempt $i/3): $(cat "$ERR_FILE"), retrying in 5s..." >&2 && sleep 5
  done
  echo "gh api $1 failed after 3 attempts: $(cat "$ERR_FILE")" >&2
  return 1
}

JOBS=$(gh_api_retry "repos/$GH_REPO/actions/runs/$RUN_ID/jobs" '.jobs[]' | jq -s '.')
# Exclude this notify job: it's still in_progress while we read the list, which
# would skew the rollup and break the date math.
COMPLETED=$(jq -c '
  map(select(.status == "completed"
             and (.name | test("^notify( |/|$)") | not)))' <<< "$JOBS")

# minutes is null-safe: a job cancelled before it starts has null timestamps,
# and must still appear (dropping it would hide a cancelled deploy).
STAGES=$(jq -c '
  sort_by(.started_at // "")
  | map({
      name: .name,
      conclusion: .conclusion,
      url: .html_url,
      minutes: (if (.started_at != null and .completed_at != null)
                then ((((.completed_at | fromdateiso8601) - (.started_at | fromdateiso8601)) / 60) | round)
                else null end),
    })
' <<< "$COMPLETED")

# "cancelled" counts as failed: a run-level cancel also cancels this job, so any
# cancelled job we can see is a per-job timeout/eviction (GitHub reports a
# timeout-minutes overrun as "cancelled", not "timed_out").
IS_FAILED='(.conclusion != "success" and .conclusion != "skipped")'
# "success" needs a real success: empty / all-skipped reports incomplete, never
# a false green.
OVERALL=$(jq -r "
  if any(.[]; $IS_FAILED) then \"failure\"
  elif any(.[]; .conclusion == \"success\") then \"success\"
  else \"incomplete\"
  end" <<< "$STAGES")
FAILED_LABELS=$(jq -r "[.[] | select($IS_FAILED) | .name] | join(\", \")" <<< "$STAGES")
# Wall-clock span, not sum: the build jobs run in parallel.
TOTAL_MIN=$(jq -r '
  map(select(.started_at != null and .completed_at != null))
  | if length == 0 then 0 else
      (map(.started_at | fromdateiso8601) | min) as $s
      | (map(.completed_at | fromdateiso8601) | max) as $e
      | (($e - $s) / 60 | round)
    end' <<< "$COMPLETED")

case "$OVERALL" in
  failure) EMOJI=":x:" ;;
  incomplete) EMOJI=":warning:" ;;
  *) EMOJI=":white_check_mark:" ;;
esac

case "$OVERALL" in
  failure) STATUS_WORD="FAILED" ;;
  incomplete) STATUS_WORD="did not complete" ;;
  *) STATUS_WORD="succeeded" ;;
esac

if [ -n "$TAG" ]; then
  TITLE="${RELEASE_NAME:-$TAG}"
  HEADLINE_TEXT="$EMOJI p0cli $PIPELINE for $TAG ($TITLE) $STATUS_WORD."
  HEADLINE_MRKDWN="$EMOJI p0cli *$PIPELINE* for *<$RELEASE_URL|$TAG>* $STATUS_WORD."
else
  HEADLINE_TEXT="$EMOJI p0cli $PIPELINE (manual run by $ACTOR) $STATUS_WORD."
  HEADLINE_MRKDWN="$HEADLINE_TEXT"
fi

FAILED_JOB_URL=$(jq -r "[.[] | select($IS_FAILED)] | .[0].url // \"\"" <<< "$STAGES")

# Separate statement, not `${SLACK_USER_MAP:-{}}`: that brace form appends a
# stray "}" when the var is set.
MAP_JSON="$SLACK_USER_MAP"
[ -z "$MAP_JSON" ] && MAP_JSON='{}'
# --arg + fromjson? (not --argjson): a malformed map loses only the mention
# instead of hard-erroring the step. Unmapped login -> "@login" (renders, no
# ping). Falls back to the actor so a manual-run failure still pings.
MENTION_LOGIN="${RELEASE_AUTHOR:-$ACTOR}"
MENTION=$(jq -rn --arg login "$MENTION_LOGIN" --arg map "$MAP_JSON" '
  (($map | fromjson? // {}) | .[$login] // "") as $id
  | if $login == "" then ""
    elif $id != "" then "<@" + $id + ">"
    else "@" + $login
    end')

# Ping on incomplete too: for a release it means no artifact was produced.
MENTION_LINE=""
if [ -n "$MENTION" ] && { [ "$OVERALL" = "failure" ] || [ "$OVERALL" = "incomplete" ]; }; then
  if [ -n "$FAILED_LABELS" ]; then
    MENTION_LINE=":bell: $MENTION — the p0cli $PIPELINE deploy did not succeed: $FAILED_LABELS"
  else
    MENTION_LINE=":bell: $MENTION — the p0cli $PIPELINE deploy did not complete (no jobs succeeded)"
  fi
  [ -n "$FAILED_JOB_URL" ] && MENTION_LINE="$MENTION_LINE (<$FAILED_JOB_URL|view job>)"
fi

HEADLINE_BLOCKS=$(jq -nc --arg h "$HEADLINE_MRKDWN" --arg m "$MENTION_LINE" '
  [{type:"section", text:{type:"mrkdwn", text:$h}}]
  + (if $m != "" then [{type:"section", text:{type:"mrkdwn", text:$m}}] else [] end)')

# Default ❌ catches every non-success/skip/cancel conclusion (timed_out, …).
DETAIL_LINES=$(jq -r '
  .[] |
  (if .conclusion == "success" then "✅"
   elif .conclusion == "skipped" then "⏭️"
   elif .conclusion == "cancelled" then "🚫"
   else "❌" end) as $e |
  (if .minutes == null then ""
   elif .minutes == 0 then " (<1m)"
   else " (\(.minutes)m)" end) as $m |
  "\($e) *\(.name)* — \(.conclusion // "unknown")\($m)"
' <<< "$STAGES")
# Slack rejects a section with empty text, which would fail the posting step.
[ -z "$DETAIL_LINES" ] && DETAIL_LINES="(no per-stage data)"

TOTAL_DISPLAY="${TOTAL_MIN}m"
[ "$TOTAL_MIN" = "0" ] && TOTAL_DISPLAY="<1m" # round() floors 0–29s to 0
FOOTER="by $ACTOR · <$RUN_URL|view run> · total $TOTAL_DISPLAY"

DETAIL_BLOCKS=$(jq -nc --arg lines "$DETAIL_LINES" --arg footer "$FOOTER" '
  [{type:"section", text:{type:"mrkdwn", text:$lines}},
   {type:"context", elements:[{type:"mrkdwn", text:$footer}]}]')

# Heredoc, not key=value: a stray newline in a key=value write corrupts every
# output after it.
{
  echo "headline_text<<HEADLINE_TEXT_EOF"
  echo "$HEADLINE_TEXT"
  echo "HEADLINE_TEXT_EOF"
  echo "headline_blocks<<HEADLINE_BLOCKS_EOF"
  echo "$HEADLINE_BLOCKS"
  echo "HEADLINE_BLOCKS_EOF"
  echo "detail_blocks<<DETAIL_BLOCKS_EOF"
  echo "$DETAIL_BLOCKS"
  echo "DETAIL_BLOCKS_EOF"
} >> "$GITHUB_OUTPUT"
