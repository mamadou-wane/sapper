# P1.5 boundary captures

The banked record of the P1.5 boundary spike probes against live AWS: account 116137268889,
us-east-1, captured 2026-08-25. The harness is `scripts/boundary-probe.sh`; each numbered JSON
file is one probe row. Every negative row ran in the same pass as a positive control, so a 403
here is evidence of a deny, not of a broken credential. Each capture records the principal that
actually made the call (`principal_actual`, asserted by the harness, `identity_check`), the
declared and observed outcomes, and the raw stderr.

## Capture index

| Capture | Principal | Expect | What it proves |
|---|---|---|---|
| `01-approver-create.json` | sapper-approver | 200 | An approval write with `If-None-Match` succeeds. Proof row: approval is authoritative and single-use. |
| `02-approver-rewrite.json` | sapper-approver | 412 | Rewriting the same approval key is refused. Single-use holds. |
| `03-approver-no-header.json` | sapper-approver | 403 | A headerless approval write is refused. On its own this is consistent with identity-policy enforcement; captures 08 and 09 are what attribute it to the bucket. |
| `04-proposer-forge-approval.json` | sapper-proposer | 403 | The proposer cannot write under `approvals/`. |
| `05-proposer-positive.json` | sapper-proposer | 200 | The proposer writes its own proposal. The paired control for capture 04. |
| `08-admin-no-header.json` | admin | 403 | The admin session holds unconditional `s3:*`, so this denial can only come from the bucket policy. Create-only is enforced by the bucket (AT-16). |
| `09-admin-with-header.json` | admin | 200 | The admin positive control for capture 08. |
| `10-proposer-lock.json` | sapper-proposer | 200 or 412 | AT-11: the §6b lock template, `locks/<sha256(resource_arn\|action)>.lock`. The expectation is computed from live state and recorded in the capture's `note` field: 200 on the first take, 412 ever after, because the lock key is deliberately stable across runs. This banked capture is from the final run and shows 412: create-only holding on the stable key. |
| `11-remediation-consumed.json` | sapper-remediation | 200 | AT-11: the `consumed/<proposal-id>` template, written through the two-hop chain (admin assumes sapper-remediator, those credentials assume sapper-remediation), the only path the trust policy allows. |
| `12-remediation-applied.json` | sapper-remediation | 200 | AT-11: the `applied/<proposal-id>.json` template, same chain. |
| `13-remediation-rollback.json` | sapper-remediation | 200 | AT-11: the `rollback/<proposal-id>.json` template, same chain. |
| `approver-identity.json` | sapper-approver | n/a | AT-10: the assumed-role session ARN (`assumed-role/sapper-approver/p15-identity`) behind the `iam::...:role/sapper-approver` form the bucket policy names. `aws:PrincipalArn` carries the role ARN for exactly this session shape. |

Captures 06 and 07 are Task 10 procedures rather than put-object rows:

| Capture | Principal | What it records |
|---|---|---|
| `06-multipart-denied-at-completion.json` | admin | AT-14, a recorded finding. A 12 MiB multipart upload passed initiation and every part (the `s3:ObjectCreationOperation` carve-out working as designed), then was denied at `CompleteMultipartUpload` because `aws s3 cp` sends no conditional header. The object was never created and the CLI aborted its own upload, zero orphaned parts. Ruled at R9: no `scratch/` exemption; the evidence store takes conditional writes only. |
| `07-runtime-role-delete.json` | sapper-proposer | AT-15. `DeleteObject` on a banked proposal refused with an explicit deny in the bucket policy (the error text itself attributes it to `DenyDeletes`, not to an ungrant), and the object afterward shows one version, zero delete markers. The delete-marker path is closed. |

## Record contract (Task 9, AT-11 read-back)

`record-contract/keys.json` lists every live object in the evidence bucket at read-back time;
every listed object round-tripped to a local file in `record-contract/`. Validated against the
amended §4/§5 six-prefix layout:

- All 19 keys match their templates exactly: `proposals/<32-hex>/s3-block-public-access/<13-digit
  ms epoch>-<32-hex>/proposal.json`, `approvals/<proposal-id>.json`, `locks/<64-hex>.lock`,
  `consumed/<proposal-id>`, `applied/<proposal-id>.json`, `rollback/<proposal-id>.json`, and the
  probe's `scratch/` objects.
- Every proposal-id is strictly url-safe base64 (`A-Za-z0-9_-`), no slash ever leaked into a key.
- One approval id was decoded and reproduces its proposal path exactly; the id stored inside the
  proposal document decodes to the same path. The §6b derivability claim holds in both directions.
- The lock key equals `sha256("arn:aws:s3:::sapper-lab-public-116137268889|s3-block-public-access")`,
  recomputed independently of the harness.

## Redaction

S3 owner canonical IDs are redacted to `REDACTED_OWNER_ID`; none appear in the captures themselves.
`grep -ril ownerid evidence/p15/*.json evidence/p15/record-contract/` returns nothing. The search is
scoped to the JSON files on purpose: run over the whole directory it matches this README, which
quotes the search term, and the claim then falsifies itself. The account ID, role ARNs, and session
ARNs stay exactly as captured, on purpose: every denial in this directory is reproducible by a reader
with the same account layout, and `PRODUCTION_GAP.md` records what that openness costs.

## Teardown proof (AT-1)

No JSON capture is defined for AT-1, so this paragraph is its banked record. On 2026-08-25
`make destroy` ran against the main stack and reported `Destroy complete! Resources: 14 destroyed.`
Afterward the evidence bucket `arn:aws:s3:::sapper-evidence-116137268889` still resolves and all
four roles (`sapper-proposer`, `sapper-remediator`, `sapper-remediation`, `sapper-approver`) still
exist. `terraform plan` on `terraform/` then reports 14 to add: the main stack is gone and the
boundary module is untouched, which is what AT-1 claims and what `PLAN.md` §8 means by "`make
destroy` does not touch it".

The test nearly went unrun. It was on its way to being deferred to Window B, on the reasoning that
destroying an already-torn-down stack proves nothing. That premise was wrong. The main stack had
been live since 2026-06-25, with the Config recorder and Security Hub billing throughout, so the
teardown was real and the test ran for real.

## Honest limits

- Probe prefixes accumulate. Deletes are denied, so every run adds a fresh proposal set. The
  bucket holds three sets from 2026-08-25: the first green run, the AT-12 falsification run, and
  the final clean run. The captures in this directory are the final run only; re-running the
  harness overwrites the local files by design, and the git-tracked copies are the record.
- The probe fixtures carry a reduced §6b field set, because Window A has no live Security Hub
  finding to build a full document from. AT-11 therefore proves the key templates, not the full
  document schemas. The schema contract is P2's to prove.
- Capture 10's first-take outcome (200 on an empty lock key) was observed in the first run but is
  not in the banked set; the banked 412 is the stronger claim, create-only on a key that already
  exists.
- The evidence store takes conditional writes only (capture 06). Any writer, admin included, must
  send `If-None-Match`, and `CopyObject` into the bucket fails outright, so exports move by
  `GetObject`, never by copy. PLAN.md §5's amendment records the same property.
