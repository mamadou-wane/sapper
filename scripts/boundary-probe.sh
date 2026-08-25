#!/usr/bin/env bash
#
# sapper P1.5 boundary probe.
#
# Table-driven. Each row declares a principal, an operation, and the outcome the
# boundary is supposed to produce. The harness runs every row, banks the raw
# result alongside the identity that actually made the call, and exits non-zero
# unless every observed outcome equals its declared one.
#
# Positive controls run in the same pass as the denials. A 403 on its own is
# indistinguishable from a broken credential, so a denial row is only evidence
# when its paired control returned 200 in the same run.
#
# An unrecognised error code is a harness failure, never a passed negative test.
# That is the line that stops "the test passed" from being mistaken for "the
# claim is proven".
#
# Eleven rows today (1-5, 8-13; 6 and 7 stay reserved). Grows three more in P5
# and becomes `make verify-boundary`.

set -uo pipefail

TF_DIR="terraform/boundary"
OUT_DIR="${OUT_DIR:-evidence/p15}"
REGION="us-east-1"

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)" || exit 1
BUCKET="$(terraform -chdir="$TF_DIR" output -raw evidence_bucket)" || exit 1

mkdir -p "$OUT_DIR"

# Committed captures are an append-only record (AGENTS.md). Refuse to
# rewrite them; pre-commit reruns and OUT_DIR overrides stay possible.
if git ls-files -- "$OUT_DIR" 2>/dev/null | grep -q .; then
  echo "refusing to overwrite tracked captures in ${OUT_DIR}; set OUT_DIR elsewhere" >&2
  exit 1
fi

FAILURES=0
RESULTS=()

# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

# sts_assume <role_name>
# Assumes <role_name> using whatever credentials are active in the current
# environment when this runs: the ambient session for a single hop, or a
# prior hop's credentials when the caller has env-prefixed this call. Prints
# AccessKeyId, SecretAccessKey, SessionToken tab-separated on stdout. Errors
# go to stderr and the caller gets a 99 return, the contract callers have
# always had.
sts_assume() {
  local role_name="$1"
  local creds

  creds="$(aws sts assume-role \
    --role-arn "arn:aws:iam::${ACCOUNT}:role/${role_name}" \
    --role-session-name "p15-probe" \
    --duration-seconds 900 \
    --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
    --output text 2>&1)"

  if [ $? -ne 0 ]; then
    echo "ASSUME_FAILED ${role_name}: ${creds}" >&2
    return 99
  fi

  printf '%s\n' "$creds"
}

# run_with_creds <tab-separated creds> <command...>
# Runs <command...> with the three AWS_* variables set from <creds> for that
# command's duration only, so no row (or hop) can leak into the next.
run_with_creds() {
  local creds="$1"; shift
  AWS_ACCESS_KEY_ID="$(echo "$creds" | cut -f1)" \
  AWS_SECRET_ACCESS_KEY="$(echo "$creds" | cut -f2)" \
  AWS_SESSION_TOKEN="$(echo "$creds" | cut -f3)" \
  "$@"
}

# run_as <principal> <command...>
# "admin" runs under the ambient SSO session. Any other value is an IAM role
# name, assumed fresh for the call, with credentials scoped through an env
# prefix rather than exported.
#
# "sapper-remediation" is the exception: its trust policy names only
# sapper-remediator's execution role, not the operator (roles.tf,
# remediation_trust). That two-hop trust chain is the design under test (D7's
# admin -> remediator -> remediation path), so a probe acting as
# sapper-remediation walks the same two hops the real remediator would,
# rather than assuming it directly from the ambient session.
run_as() {
  local principal="$1"; shift

  if [ "$principal" = "admin" ]; then
    "$@"
    return $?
  fi

  if [ "$principal" = "sapper-remediation" ]; then
    local hop1 hop2
    hop1="$(sts_assume sapper-remediator)" || return 99
    hop2="$(run_with_creds "$hop1" sts_assume sapper-remediation)" || return 99
    run_with_creds "$hop2" "$@"
    return $?
  fi

  local creds
  creds="$(sts_assume "$principal")" || return 99
  run_with_creds "$creds" "$@"
  return $?
}

# whoami_as <principal> -> the ARN that principal actually presents to AWS. Read
# from a separate assume of the same role: same role and session name, so the
# string is identical, but it is not the probe call's own session. For
# sapper-remediation this is a separate two-hop chain, not a session shared
# with the probe call's own two hops.
whoami_as() {
  run_as "$1" aws sts get-caller-identity --query Arn --output text 2>/dev/null
}

# ---------------------------------------------------------------------------
# Outcome classification
# ---------------------------------------------------------------------------

# classify <exit_code> <stderr_text>
classify() {
  local rc="$1" err="$2"

  if [ "$rc" -eq 0 ]; then echo "200"; return; fi
  if [ "$rc" -eq 99 ]; then echo "ASSUME_FAILED"; return; fi

  case "$err" in
    *PreconditionFailed*)         echo "412" ;;
    *ConditionalRequestConflict*) echo "409" ;;
    *AccessDenied*)               echo "403" ;;
    *)                            echo "UNKNOWN" ;;
  esac
}

# ---------------------------------------------------------------------------
# One probe
# ---------------------------------------------------------------------------

# probe <n> <name> <matrix_row> <principal> <expected> <key> <body_file> <use_header> [note]
# <note> is optional context on how <expected> was arrived at (row 10's
# expectation is computed from live state, not a fixed declaration); it is
# empty for every other row and adds nothing to their capture.
probe() {
  local n="$1" name="$2" matrix="$3" principal="$4" expected="$5"
  local key="$6" body="$7" use_header="$8" note="${9:-}"

  # Harness self-test (AT-12). Setting P15_FORCE_FAIL to a probe number inverts
  # that row's declared expectation, so a correctly working boundary produces a
  # failing run. A harness that cannot fail is not evidence, and proving that
  # through an env var beats editing the table and reverting it, which leaves
  # the script dirty if the run dies in between.
  if [ "${P15_FORCE_FAIL:-}" = "$n" ]; then
    if [ "$expected" = "200" ]; then expected="403"; else expected="200"; fi
    echo "  [self-test] row ${n} expectation inverted to ${expected}"
  fi

  local actual_arn stderr_file rc observed
  actual_arn="$(whoami_as "$principal")"
  stderr_file="$(mktemp)"

  local -a args=(s3api put-object --bucket "$BUCKET" --key "$key"
                 --body "$body" --region "$REGION")
  if [ "$use_header" = "yes" ]; then
    args+=(--if-none-match '*')
  fi

  run_as "$principal" aws "${args[@]}" >/dev/null 2>"$stderr_file"
  rc=$?
  observed="$(classify "$rc" "$(cat "$stderr_file")")"

  # A capture proves who made the call only if the identity is checked, not
  # merely banked. The declared role must appear in the assumed-role ARN, and
  # the ambient admin session must not be one of the sapper roles.
  local identity_ok="yes"
  case "$principal" in
    admin) case "$actual_arn" in *assumed-role/sapper-*) identity_ok="no" ;; esac ;;
    *)     case "$actual_arn" in *"assumed-role/${principal}/"*) : ;; *) identity_ok="no" ;; esac ;;
  esac

  local status="PASS"
  if [ "$observed" != "$expected" ] || [ "$identity_ok" = "no" ]; then
    status="FAIL"
    FAILURES=$((FAILURES + 1))
  fi

  # Comma placement: captured_at stops being the last field only when a note
  # is present, so the comma has to travel with it rather than sit fixed.
  local note_json=""
  if [ -n "$note" ]; then
    note_json=",
  \"note\": $(printf '%s' "$note" | jq -Rs .)"
  fi

  cat > "${OUT_DIR}/$(printf '%02d' "$n")-${name}.json" <<EOF
{
  "probe": "$(printf '%02d' "$n")-${name}",
  "matrix_row": "${matrix}",
  "principal_declared": "${principal}",
  "principal_actual": "${actual_arn}",
  "identity_check": "${identity_ok}",
  "operation": "s3:PutObject arn:aws:s3:::${BUCKET}/${key}",
  "if_none_match": "$([ "$use_header" = yes ] && echo '*' || echo null)",
  "expected": "${expected}",
  "observed": "${observed}",
  "exit_code": ${rc},
  "stderr": $(jq -Rs . < "$stderr_file"),
  "status": "${status}",
  "captured_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"${note_json}
}
EOF

  rm -f "$stderr_file"
  local row
  row="$(printf '%-34s %-18s expect %-4s got %-4s %s' \
    "$(printf '%02d' "$n")-${name}" "$principal" "$expected" "$observed" "$status")"
  RESULTS+=("$row")
  printf '  %s\n' "$row"
}

# ---------------------------------------------------------------------------
# Fixtures: real §6b shapes at real §6b keys
# ---------------------------------------------------------------------------

FIX="$(mktemp -d)"
LAB_ARN="arn:aws:s3:::sapper-lab-public-${ACCOUNT}"

RESOURCE_KEY="$(printf '%s' "$LAB_ARN" | shasum -a 256 | cut -c1-32)"
ACTION="s3-block-public-access"
ULID="$(( $(date +%s) * 1000 ))-$(uuidgen | tr -d - | tr 'A-Z' 'a-z')"
PID_PATH="${RESOURCE_KEY}/${ACTION}/${ULID}"
PROPOSAL_ID="$(printf '%s' "$PID_PATH" | base64 | tr '+/' '-_' | tr -d '=' | tr -d '\n')"

PROPOSAL_KEY="proposals/${PID_PATH}/proposal.json"
APPROVAL_KEY="approvals/${PROPOSAL_ID}.json"

# The lock key is deliberately stable (§6b scopes it to resource+action, not
# per run): locks/<sha256(resource_arn + "|" + action)>.lock, full digest, no
# truncation (PLAN.md:455). That is a different hash from RESOURCE_KEY above,
# which is truncated and used only for proposal/lock *path* namespacing
# elsewhere, not for this key.
LOCK_KEY="locks/$(printf '%s' "${LAB_ARN}|${ACTION}" | shasum -a 256 | cut -d' ' -f1).lock"

# The correct outcome for row 10 depends on whether an earlier run already
# took this lock: 200 on first write, 412 ever after. Both prove create-only
# mechanics on the template key, so the expectation is read from live state
# rather than declared fixed. A head-object error the harness cannot
# classify (anything but "the key does not exist yet") fails the run closed,
# same philosophy as classify()'s UNKNOWN: a harness that cannot tell what
# happened is not evidence.
LOCK_HEAD_ERR="$(mktemp)"
if aws s3api head-object --bucket "$BUCKET" --key "$LOCK_KEY" --region "$REGION" \
     >/dev/null 2>"$LOCK_HEAD_ERR"; then
  LOCK_PREEXISTING="yes"
  LOCK_EXPECT="412"
else
  case "$(cat "$LOCK_HEAD_ERR")" in
    *"Not Found"*|*404*)
      LOCK_PREEXISTING="no"
      LOCK_EXPECT="200"
      ;;
    *)
      echo "head-object on ${LOCK_KEY} failed in a way the harness cannot classify:" >&2
      cat "$LOCK_HEAD_ERR" >&2
      rm -f "$LOCK_HEAD_ERR"
      exit 1
      ;;
  esac
fi
rm -f "$LOCK_HEAD_ERR"

LOCK_NOTE="expectation computed from live state: lock key preexisting = ${LOCK_PREEXISTING}"

cat > "${FIX}/proposal.json" <<EOF
{
  "schema_version": 1,
  "proposal_id": "${PROPOSAL_ID}",
  "provenance": "P15_PROBE",
  "control_id": "S3.8",
  "resource_arn": "${LAB_ARN}",
  "remediation_action": "${ACTION}",
  "before_state": {
    "configuration_present": false,
    "BlockPublicAcls": false, "IgnorePublicAcls": false,
    "BlockPublicPolicy": false, "RestrictPublicBuckets": false
  },
  "plan": {
    "action": "${ACTION}",
    "target_arn": "${LAB_ARN}",
    "set": { "BlockPublicAcls": true, "IgnorePublicAcls": true,
             "BlockPublicPolicy": true, "RestrictPublicBuckets": true }
  },
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

cat > "${FIX}/approval.json" <<EOF
{
  "schema_version": 1,
  "proposal_id": "${PROPOSAL_ID}",
  "proposal_key": "${PROPOSAL_KEY}",
  "provenance": "P15_PROBE",
  "approved_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

echo "p15 probe scratch" > "${FIX}/scratch.txt"

# §6b gives no body shape for locks/*.lock or the runtime-role markers, only
# the key templates. Minimal fixtures, marked P15_PROBE like the rest.
cat > "${FIX}/lock.json" <<EOF
{
  "proposal_id": "${PROPOSAL_ID}",
  "provenance": "P15_PROBE",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

cat > "${FIX}/marker.json" <<EOF
{
  "proposal_id": "${PROPOSAL_ID}",
  "provenance": "P15_PROBE"
}
EOF

# ---------------------------------------------------------------------------
# The table
# ---------------------------------------------------------------------------

echo "sapper P1.5 boundary probe"
echo "  bucket:      ${BUCKET}"
echo "  proposal_id: ${PROPOSAL_ID}"
echo ""

#     n  name                     matrix row                              principal          expect key              body                  header
probe 1 "approver-create"        "Approval is authoritative and single-use" sapper-approver    200 "$APPROVAL_KEY"  "${FIX}/approval.json" yes
probe 2 "approver-rewrite"       "Approval is authoritative and single-use" sapper-approver    412 "$APPROVAL_KEY"  "${FIX}/approval.json" yes
probe 3 "approver-no-header"     "Create-only is enforced by the bucket"    sapper-approver    403 "$APPROVAL_KEY"  "${FIX}/approval.json" no
probe 4 "proposer-forge-approval" "Proposer cannot forge approvals"         sapper-proposer    403 "approvals/probe-${PROPOSAL_ID}.json" "${FIX}/approval.json" yes
probe 5 "proposer-positive"      "Proposer cannot forge approvals (control)" sapper-proposer   200 "$PROPOSAL_KEY"  "${FIX}/proposal.json" yes
probe 8 "admin-no-header"        "Create-only is enforced by the bucket"    admin              403 "scratch/probe-${PROPOSAL_ID}.txt" "${FIX}/scratch.txt" no
probe 9 "admin-with-header"      "Create-only is enforced by the bucket (control)" admin       200 "scratch/probe-${PROPOSAL_ID}.txt" "${FIX}/scratch.txt" yes

# AT-11 extension: the §6b key templates that probes 1-9 never touch, proven
# as AT-11 key-template rows rather than as §13 proof-matrix claims (§13 has
# sixteen rows; these are not among them). LOCK_KEY, LOCK_EXPECT, and
# LOCK_NOTE are computed above, in the fixtures section, alongside the
# script's other computed keys. Rows 11-13 also prove the sapper-remediation
# two-hop trust chain, not just the key template, since that principal
# cannot be reached any other way.
probe 10 "proposer-lock"         "AT-11: §6b key template (locks)"     sapper-proposer    "$LOCK_EXPECT" "$LOCK_KEY" "${FIX}/lock.json" yes "$LOCK_NOTE"
probe 11 "remediation-consumed"  "AT-11: §6b key template (consumed)"  sapper-remediation 200 "consumed/${PROPOSAL_ID}" "${FIX}/marker.json" yes
probe 12 "remediation-applied"   "AT-11: §6b key template (applied)"   sapper-remediation 200 "applied/${PROPOSAL_ID}.json" "${FIX}/marker.json" yes
probe 13 "remediation-rollback"  "AT-11: §6b key template (rollback)"  sapper-remediation 200 "rollback/${PROPOSAL_ID}.json" "${FIX}/marker.json" yes

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

echo ""
if [ "$FAILURES" -eq 0 ]; then
  echo "PASS: ${#RESULTS[@]} rows, every observed outcome matched its declaration."
else
  echo "FAIL: ${FAILURES} of ${#RESULTS[@]} rows did not match. Captures are in ${OUT_DIR}."
fi

rm -rf "$FIX"
exit "$FAILURES"
