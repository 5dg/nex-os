SHELL := /bin/bash
.PHONY: dev start down logs migrate seed test verify-local build workspace-install workspace-check terraform-check preflight

dev:
	./scripts/local.sh up
start:
	./scripts/local.sh start
down:
	./scripts/local.sh down
logs:
	./scripts/local.sh logs
migrate:
	./scripts/local.sh migrate
seed:
	./scripts/local.sh seed
test:
	go test ./...
verify-local:
	./scripts/verify-local.sh
build:
	go build ./services/control/cmd/...
workspace-install:
	cd apps/workspace && npm ci
workspace-check:
	cd apps/workspace && npm run typecheck && npm run build
terraform-check:
	terraform -chdir=deploy/terraform fmt -check
	terraform -chdir=deploy/terraform init -backend=false -input=false
	terraform -chdir=deploy/terraform validate
preflight:
	./scripts/govcloud-preflight.sh

.PHONY: qualification-build qualification-build-host qualification-up qualification-down qualification-ready
qualification-build:
	./scripts/qualification.sh build
qualification-build-host:
	./scripts/qualification.sh build-host
qualification-up:
	./scripts/qualification.sh up
qualification-down:
	./scripts/qualification.sh down
qualification-ready:
	./scripts/qualification.sh ready
