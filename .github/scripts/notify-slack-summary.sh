#!/usr/bin/env bash
#
# Build the Slack "deploy summary" payload for a release deploy run and write it
# to $GITHUB_OUTPUT (headline_text, headline_blocks, detail_blocks) for the
# notify-slack.yml reusable workflow to post. Reports a failure when any job did
# not succeed, and @-mentions the release author (or the manual-run actor).
#
# Reads from the environment (all set by the workflow's `env:` block):
#   GH_TOKEN GH_REPO RUN_ID ACTOR PIPELINE RUN_URL
#   TAG RELEASE_NAME RELEASE_URL RELEASE_AUTHOR   (empty on workflow_dispatch)
#   SLACK_USER_MAP                                (GitHub login -> Slack ID JSON)
#
# -eo pipefail (not -u): a failed `gh_api_retry | jq -s` must propagate out of
# the pipe and fail the step rather than silently yielding JOBS=[] and a green
# job — the exact silent failure this notifier exists to prevent.
set -eo pipefail

# Retries transient GitHub API failures 3x, matching the convention in app's
# notify-slack.yml.
# stderr goes to a file, never into OUT: a gh deprecation/rate-limit warning
# merged into stdout would make the downstream `jq -s` choke on non-JSON and,
# under pipefail, kill the whole step. The file is surfaced only in the failure
# diagnostic.
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

# Every completed job in this run EXCEPT this notify job: its own entry is
# fetched WHILE it is still executing (status "in_progress", null completed_at),
# which would skew both the status rollup and the wall-clock math. Computed once
# and reused so the status and the per-stage detail can never disagree about
# which jobs count.
JOBS=$(gh_api_retry "repos/$GH_REPO/actions/runs/$RUN_ID/jobs" '.jobs[]' | jq -s '.')
COMPLETED=$(jq -c '
  map(select(.status == "completed"
             and (.name | test("^notify( |/|$)") | not)))' <<< "$JOBS")

# One line per completed job, in start order. A job cancelled while still queued
# has null timestamps, so minutes is computed null-safely rather than filtering
# the job out — dropping it would hide a cancelled deploy from both the status
# and the detail entirely.
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

# A job counts as failed unless it succeeded or was skipped. "cancelled" IS
# counted as a failure: a run-level cancel also cancels this notify job, so any
# cancelled job this notifier can observe is a per-job timeout or eviction
# (GitHub reports a timeout-minutes overrun as "cancelled", not "timed_out") —
# i.e. a build that produced no artifact, which must ping.
IS_FAILED='(.conclusion != "success" and .conclusion != "skipped")'
# "success" requires at least one job to have actually succeeded. An empty job
# set, or a run where every job was skipped and none succeeded, is reported as
# incomplete (:warning:) — never a green checkmark, which would be the silent
# false-positive this notifier exists to prevent.
OVERALL=$(jq -r "
  if any(.[]; $IS_FAILED) then \"failure\"
  elif any(.[]; .conclusion == \"success\") then \"success\"
  else \"incomplete\"
  end" <<< "$STAGES")
FAILED_LABELS=$(jq -r "[.[] | select($IS_FAILED) | .name] | join(\", \")" <<< "$STAGES")
# Wall-clock span of the run (the build jobs run in parallel), computed from the
# jobs that actually started so it matches what the UI shows.
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

# Headline: release-centric, with a workflow_dispatch fallback.
if [ -n "$TAG" ]; then
  TITLE="${RELEASE_NAME:-$TAG}"
  HEADLINE_TEXT="$EMOJI p0cli $PIPELINE for $TAG ($TITLE) $STATUS_WORD."
  HEADLINE_MRKDWN="$EMOJI p0cli *$PIPELINE* for *<$RELEASE_URL|$TAG>* $STATUS_WORD."
else
  HEADLINE_TEXT="$EMOJI p0cli $PIPELINE (manual run by $ACTOR) $STATUS_WORD."
  HEADLINE_MRKDWN="$HEADLINE_TEXT"
fi

# Direct link to the first job that did not succeed (failed, cancelled, or timed
# out), using the same predicate as OVERALL.
FAILED_JOB_URL=$(jq -r "[.[] | select($IS_FAILED)] | .[0].url // \"\"" <<< "$STAGES")

# @-mention the release author on failure, via the SLACK_USER_MAP repo variable
# (GitHub login -> Slack member ID), same pattern as app. Falls back to plain
# "@login" text (renders, does not ping) if the login isn't in the map.
#   NB: `${SLACK_USER_MAP:-{}}` looks equivalent but is a bash brace-counting
#   trap — when the var IS set, bash still appends an extra "}" from the default
#   word. Do the "default to {}" check as a separate statement instead.
MAP_JSON="$SLACK_USER_MAP"
[ -z "$MAP_JSON" ] && MAP_JSON='{}'
# --arg (not --argjson): a malformed SLACK_USER_MAP variable would make
# --argjson hard-error and, under pipefail, kill the whole step. fromjson?
# swallows a parse failure instead, so a bad map loses only the mention, not the
# notification.
# The release author if this was a release, else whoever triggered the manual
# run — so a failed workflow_dispatch deploy still pings someone.
MENTION_LOGIN="${RELEASE_AUTHOR:-$ACTOR}"
MENTION=$(jq -rn --arg login "$MENTION_LOGIN" --arg map "$MAP_JSON" '
  (($map | fromjson? // {}) | .[$login] // "") as $id
  | if $login == "" then ""
    elif $id != "" then "<@" + $id + ">"
    else "@" + $login
    end')

# Ping on failure AND incomplete: "incomplete" now means no job succeeded (all
# skipped / nothing ran), which for a release still means no artifact was
# produced and someone should look.
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

# Default emoji is ❌ so it covers every non-success/skip/cancel conclusion
# (failure, timed_out, action_required, …), matching OVERALL. Minutes are
# omitted for a job that never started (null timestamps).
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
# Slack's chat.postMessage rejects a section with empty mrkdwn text; with
# errors: true that would fail the posting step outright.
[ -z "$DETAIL_LINES" ] && DETAIL_LINES="(no per-stage data)"

# "<1m" rather than "0m" for a sub-minute run (round() floors 0–29s to 0).
TOTAL_DISPLAY="${TOTAL_MIN}m"
[ "$TOTAL_MIN" = "0" ] && TOTAL_DISPLAY="<1m"
FOOTER="by $ACTOR · <$RUN_URL|view run> · total $TOTAL_DISPLAY"

DETAIL_BLOCKS=$(jq -nc --arg lines "$DETAIL_LINES" --arg footer "$FOOTER" '
  [{type:"section", text:{type:"mrkdwn", text:$lines}},
   {type:"context", elements:[{type:"mrkdwn", text:$footer}]}]')

# Heredoc form, not "key=value" lines: a stray newline in a "key=value" write
# silently corrupts every output after it.
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
