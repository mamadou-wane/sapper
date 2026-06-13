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
	@echo "Real today: fmt, validate, scan, deploy, destroy."
	@echo "Not built yet (honest stubs): remediate, verify-boundary, demo."

# ---------------------------------------------------------------------------
# Real targets: these wrap commands already run by hand
# ---------------------------------------------------------------------------

.PHONY: setup
setup: ## Initialize Terraform working dir (downloads providers)
	$(TF) init

.PHONY: fmt
fmt: ## Check Terraform formatting (non-mutating; matches CI)
	$(TF) fmt -check -recursive

.PHONY: validate
validate: ## Validate Terraform configuration offline
	$(TF) init -backend=false
	$(TF) validate

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
# Honest stubs: Phase 1 and Phase 4 work that does not exist yet
# ---------------------------------------------------------------------------

.PHONY: remediate
remediate: ## [NOT BUILT] Phase 1: assume bounded role, verify approval, apply fix, capture evidence
	@echo "remediate: not built yet."
	@echo "Phase 1 will: assume the bounded remediation role (not admin), verify the"
	@echo "approval binding (finding ID, resource ARN, plan-hash), re-read live state and"
	@echo "abort on drift, flip the bucket private, capture after-state, and verify."

.PHONY: verify-boundary
verify-boundary: ## [NOT BUILT] Phase 1: run the 3 negative IAM tests, capture each AccessDenied
	@echo "verify-boundary: not built yet."
	@echo "Phase 1 will: prove all three boundary claims by attempting forbidden actions"
	@echo "from the remediation and proposer roles and capturing each AccessDenied as a"
	@echo "committed evidence artifact."

.PHONY: demo
demo: ## [NOT BUILT] Phase 4: drive the end-to-end run via the demo twin rule (sapper.demo)
	@echo "demo: not built yet."
	@echo "Phase 4 will: inject the representative event through the demo twin rule"
	@echo "(sapper.demo source), run detect -> propose -> approve -> remediate -> verify,"
	@echo "and label the run DEMO. Real findings flow the identical real-source path."
