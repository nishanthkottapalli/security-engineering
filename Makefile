SHELL := /bin/bash
PYTHON ?= python3
COMPOSE ?= docker compose

.PHONY: help setup test validate demo up down logs smoke triage-demo detection-demo \
        docker-demo full-demo sbom wazuh-test terraform-fmt terraform-validate terraform-test terraform-plan \
        aws-apply aws-destroy vagrant-up vagrant-destroy clean

help:
	@printf '%s\n' \
	  'setup              Create a local virtual environment and install dependencies' \
	  'test               Run unit and integration-safe tests' \
	  'validate           Compile, lint XML/YAML/JSON and run tests' \
	  'demo                Run detection and vulnerability-triage demos locally' \
	  'up                  Start the FastAPI/PostgreSQL worker stack with Docker' \
	  'smoke               Start stack and run API smoke tests' \
	  'docker-demo         Run detection and triage demos inside Docker' \
	  'full-demo           Execute phases 1-4 through Docker and Terraform mocks' \
	  'sbom                Generate a CycloneDX SBOM with Syft' \
	  'wazuh-test          Run Wazuh decoder/rule tests in the Wazuh container' \
	  'terraform-test      Run Terraform mock-provider tests without AWS credentials' \
	  'terraform-plan      Create a real AWS plan (credentials required)' \
	  'aws-apply           Apply the AWS security baseline after explicit approval' \
	  'vagrant-up          Provision the Docker lab inside VirtualBox' \
	  'clean               Remove generated artefacts'

setup:
	$(PYTHON) -m venv .venv
	. .venv/bin/activate && python -m pip install --upgrade pip && pip install -e '.[dev]'

validate:
	$(PYTHON) -m compileall -q src tests scripts
	$(PYTHON) scripts/validate_repository.py
	$(PYTHON) -m pytest

test:
	$(PYTHON) -m pytest

demo: detection-demo triage-demo

detection-demo:
	PYTHONPATH=src $(PYTHON) -m secops_lab.cli detection replay \
	  tests/fixtures/detection/ssh_compromise.log --output lab-output/detection-alerts.json

triage-demo:
	PYTHONPATH=src $(PYTHON) -m secops_lab.cli triage run \
	  tests/fixtures/pip_audit/pip-audit.json \
	  tests/fixtures/trivy/trivy.json \
	  tests/fixtures/grype/grype.json \
	  tests/fixtures/checkov/checkov.json \
	  --output-dir lab-output/triage

up:
	$(COMPOSE) up -d --build postgres migrate api worker gateway

smoke:
	bash ./scripts/docker_smoke.sh

down:
	$(COMPOSE) down --remove-orphans

logs:
	$(COMPOSE) logs -f --tail=200

docker-demo:
	mkdir -p lab-output
	LOCAL_UID=$$(id -u) LOCAL_GID=$$(id -g) $(COMPOSE) --profile demo run --rm detection-demo
	LOCAL_UID=$$(id -u) LOCAL_GID=$$(id -g) $(COMPOSE) --profile demo run --rm triage-demo

full-demo: smoke docker-demo sbom wazuh-test terraform-test
	@echo "All executable phase demonstrations completed."

sbom:
	bash ./scripts/generate_sbom.sh

wazuh-test:
	$(COMPOSE) --profile wazuh run --rm wazuh-logtest

terraform-fmt:
	docker run --rm -v "$$(pwd)/terraform/aws-foundation:/workspace" -w /workspace \
	  hashicorp/terraform:1.12.2 fmt -recursive -check

terraform-validate:
	docker run --rm -v "$$(pwd)/terraform/aws-foundation:/workspace" -w /workspace \
	  --entrypoint /bin/sh hashicorp/terraform:1.12.2 -lc 'terraform init -backend=false && terraform validate'

terraform-test:
	docker run --rm -v "$$(pwd)/terraform/aws-foundation:/workspace" -w /workspace \
	  --entrypoint /bin/sh hashicorp/terraform:1.12.2 -lc 'terraform init -backend=false && terraform test -verbose'

terraform-plan:
	$(COMPOSE) --profile terraform run --rm terraform \
	  'terraform init && terraform plan -out=/workspace/lab-output/aws-foundation.tfplan'

aws-apply:
	@echo 'This creates billable AWS resources. Review the plan before continuing.'
	$(COMPOSE) --profile terraform run --rm terraform \
	  'terraform init && terraform apply /workspace/lab-output/aws-foundation.tfplan'

aws-destroy:
	$(COMPOSE) --profile terraform run --rm terraform \
	  'terraform init && terraform destroy'

vagrant-up:
	vagrant up --provider=virtualbox

vagrant-destroy:
	vagrant destroy -f

clean:
	rm -rf lab-output/* uploads/* .pytest_cache .ruff_cache .mypy_cache .coverage htmlcov
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type d -name "*.egg-info" -prune -exec rm -rf {} +
	touch lab-output/.gitkeep uploads/.gitkeep
