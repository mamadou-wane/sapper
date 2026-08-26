# sapper operator Makefile
#
# Convention: every target either does real work or says plainly it is
# not built yet. Nothing here claims more than the repo can do today.
#
# Scope guard: routine targets operate ONLY on terraform/. The remote
# state backend lives in terraform/bootstrap/ and is deliberately
# excluded from deploy/destroy so teardown can never touch the state
# bucket. Bootstrap is managed by hand, rarely, on purpose.

TF_DIR        := terraform
TF            := terraform -chdir=$(TF_DIR)
TF_BOUNDARY   := terraform -chdir=terraform/boundary
CHECKOV_SKIP  := --skip-path terraform/bootstrap

# Pinned for scanner parity with CI (see ADR-0002): the graph framework
# only loads under Python 3.12, so local scans must run the same line CI runs.
CHECKOV := ./.venv-checkov312/bin/checkov -d terraform --skip-path terraform/bootstrap

.DEFAULT_GOAL := help

# ---------------------------------------------------------------------------
# Help (default target)
# ---------------------------------------------------------------------------

.PHONY: help
help: ## Show this help
	@echo "sapper available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Real today: setup-scan, setup-test, fmt, validate, scan, test, plan, deploy,"
	@echo "            destroy, boundary-init, boundary-plan, boundary-apply, boundary-probe."
	@echo "Not built yet (honest stubs): remediate, rollback, verify-boundary, demo."
	@echo "No AWS credentials needed: setup-scan, setup-test, fmt, validate, scan, test."
	@echo ""
	@echo "Lifecycle: deploy/destroy operate on terraform/ only. terraform/boundary/"
	@echo "and terraform/bootstrap/ are persistent and hand-applied; destroy cannot"
	@echo "reach either, which is what makes the evidence store durable."

# ---------------------------------------------------------------------------
# Real targets: these wrap commands already run by hand
# ---------------------------------------------------------------------------

.PHONY: setup
setup: ## Initialize Terraform working dir (downloads providers; needs backend access)
	$(TF) init

# The scanner venv is gitignored, so a fresh clone has no ./.venv-checkov312.
# Without this target, `make scan` and `make deploy` fail on a clean checkout.
.PHONY: setup-scan
setup-scan: ## Create the pinned Python 3.12 venv the Checkov scan requires
	@command -v python3.12 >/dev/null 2>&1 || { \
		echo "python3.12 not found. ADR-0002: Checkov's graph framework only loads"; \
		echo "under 3.12, so scanner parity with CI requires it. Install it first."; \
		exit 1; \
	}
	python3.12 -m venv .venv-checkov312
	./.venv-checkov312/bin/pip install --quiet --upgrade pip
	./.venv-checkov312/bin/pip install --quiet 'checkov==3.2.530'
	@echo "Scanner venv ready. Run 'make scan' and check the summary line: a result"
	@echo "with 0 skipped means the graph framework did not load and the scan is"
	@echo "silently degraded (ADR-0002). Parity is read from the summary, not --version."

# The project venv is gitignored, so a fresh clone has no ./.venv. Same seam as
# setup-scan: without this target, `make test` fails on a clean checkout.
.PHONY: setup-test
setup-test: ## Create the Python 3.12 venv and install sapper with dev dependencies
	@command -v python3.12 >/dev/null 2>&1 || { \
		echo "python3.12 not found. PLAN.md §12 pins the package to the Lambda"; \
		echo "runtime version and the Checkov parity line (ADR-0002). Install it first."; \
		exit 1; \
	}
	python3.12 -m venv .venv
	./.venv/bin/pip install --quiet --upgrade pip
	./.venv/bin/pip install --quiet -e '.[dev]'

.PHONY: test
test: ## Run pytest, ruff, and mypy on src/ (parity-locked to CI)
	./.venv/bin/pytest
	./.venv/bin/ruff check src tests
	./.venv/bin/mypy

.PHONY: fmt
fmt: ## Check Terraform formatting (non-mutating; matches CI)
	$(TF) fmt -check -recursive

.PHONY: validate
validate: ## Validate Terraform configuration offline
	$(TF) init -backend=false
	$(TF) validate
	$(TF_BOUNDARY) init -backend=false
	$(TF_BOUNDARY) validate

.PHONY: scan
scan: ## Run the Checkov guardrail scan (parity-locked to CI; Python 3.12)
	$(CHECKOV)

.PHONY: plan
plan: ## Show the Terraform execution plan
	$(TF) plan

.PHONY: deploy
deploy: ## Apply Terraform: lab resources + detective services (NOT bootstrap)
	@echo ">> Standing order: scan before apply."
	$(CHECKOV)
	$(TF) apply

# destroy is destructive AND cost-affecting in reverse: tearing down the
# terraform/ stack disables Security Hub standards and stops the Config
# recorder (both Terraform-managed since T4/T5), which is exactly what stops
# them billing. Bootstrap/state bucket is untouched by design. Guarded.
.PHONY: destroy
destroy: ## Tear down lab + detective services to zero cost (guarded; never bootstrap)
	@echo "This destroys the terraform/ stack: lab resources AND the detective"
	@echo "services (Security Hub standards, Config recorder). It does NOT touch"
	@echo "terraform/bootstrap/ or the remote-state bucket."
	@echo ""
	@read -p "Type 'destroy' to confirm: " ans; \
	if [ "$$ans" = "destroy" ]; then \
		$(TF) destroy; \
	else \
		echo "Aborted."; \
	fi

# ---------------------------------------------------------------------------
# The boundary module: durable, hand-applied, never reached by deploy/destroy.
#
# There is deliberately no boundary-destroy target. The evidence bucket is
# created once and never recreated (PLAN.md §8), and four IAM roles cost nothing
# to leave in place.
# ---------------------------------------------------------------------------

.PHONY: boundary-init
boundary-init: ## Initialize the persistent boundary module (its own state)
	$(TF_BOUNDARY) init

.PHONY: boundary-plan
boundary-plan: ## Plan the boundary module and save it for review and apply
	$(TF_BOUNDARY) plan -out=boundary.tfplan

# Applying a saved plan does not prompt for confirmation: the R5 read of the
# saved plan is the approval. Terraform refuses a stale plan file if state or
# config changed since it was written, which forces a fresh plan and a fresh
# R5.
.PHONY: boundary-apply
boundary-apply: ## Apply the saved boundary plan. destroy can never reach these resources
	@echo ">> Standing order: scan before apply."
	$(CHECKOV)
	$(TF_BOUNDARY) apply boundary.tfplan

.PHONY: boundary-probe
boundary-probe: ## Run the P1.5 boundary probes and bank the captures
	./scripts/boundary-probe.sh

# ---------------------------------------------------------------------------
# Honest stubs: Phase 1 and Phase 4 work that does not exist yet
# ---------------------------------------------------------------------------

.PHONY: remediate
remediate: ## [NOT BUILT] P4: render the plan, take approval, let the remediator apply it
	@echo "remediate: not built yet."
	@echo "P4 will: assume the sapper-approver role (which holds no mutating permission"
	@echo "and cannot assume the bounded role), render the dry-run plan as the exact bytes"
	@echo "that were hashed, confirm by typed bucket name, and write the approval object."
	@echo "Writing that object is the single point of commitment: an S3 event triggers the"
	@echo "remediator, which verifies the binding, claims consumed/<proposal-id> so the"
	@echo "approval burns, re-reads live state and aborts on drift, then applies the fix"
	@echo "under the bounded role and captures after-state."

.PHONY: rollback
rollback: ## [NOT BUILT] P4: restore the captured before_state for a proposal, with evidence
	@echo "rollback: not built yet."
	@echo "P4 will: read the applied record for a proposal id, restore the before_state"
	@echo "captured at propose time, and write rollback/<proposal-id> recording who ran it,"
	@echo "when, and the state before and after. Runs under the bounded role: restoring the"
	@echo "BPA flags is the same API on the same allowlisted ARN, so it needs no new grant."
	@echo "No approval required. Undoing to a captured prior state is not the action the"
	@echo "approval boundary gates, and the rollback is evidenced."

.PHONY: verify-boundary
verify-boundary: ## [NOT BUILT] P5: run the 8 negative IAM tests, capture each AccessDenied
	@echo "verify-boundary: not built yet."
	@echo "P5 will: attempt eight forbidden actions and capture each AccessDenied as a"
	@echo "committed artifact. Proposer: target mutation, approval write, Security Hub"
	@echo "write, sts:AssumeRole. Remediator: approval write, delete of a consumed marker."
	@echo "Approver: target mutation, sts:AssumeRole on the bounded role."
	@echo "Each is paired with a positive control in the same run, so a denial cannot be"
	@echo "confused with a broken credential. The account administrator defeats all of"
	@echo "this and is out of scope: see the threat model in PRODUCTION_GAP.md."

.PHONY: demo
demo: ## [NOT BUILT] Phase 4: drive the end-to-end run via the demo twin rule (sapper.demo)
	@echo "demo: not built yet."
	@echo "Phase 4 will: inject the representative event through the demo twin rule"
	@echo "(sapper.demo source), run detect -> propose -> approve -> remediate -> verify,"
	@echo "and label the run DEMO. Real findings flow the identical real-source path."
