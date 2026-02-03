VENV := .venv
VENV_BIN := $(VENV)/bin
OUTPUT_DIR := out

# Create venv and install project with dev dependencies.
# Re-runs when pyproject.toml or uv.lock change.
$(VENV)/.stamp: pyproject.toml uv.lock
	uv sync --dev
	touch $@

help: ## Show this help message
	@grep -E '^[a-zA-Z_.-]+:.*##' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

setup: $(VENV)/.stamp ## Create local development virtualenv

run: $(VENV)/.stamp ## Run gdoc2netcfg (use ARGS= for subcommands)
	$(VENV_BIN)/gdoc2netcfg $(ARGS)

generate: $(VENV)/.stamp ## Generate configs into out/ (use ARGS= for specific generators)
	$(VENV_BIN)/gdoc2netcfg generate --output-dir $(OUTPUT_DIR) $(ARGS)

fetch: $(VENV)/.stamp ## Download CSVs from Google Sheets
	$(VENV_BIN)/gdoc2netcfg fetch

scan: $(VENV)/.stamp ## Run reachability check then all network scans
	$(VENV_BIN)/gdoc2netcfg reachability
	$(VENV_BIN)/gdoc2netcfg sshfp
	$(VENV_BIN)/gdoc2netcfg ssl-certs
	$(VENV_BIN)/gdoc2netcfg snmp
	$(VENV_BIN)/gdoc2netcfg bmc-firmware
	$(VENV_BIN)/gdoc2netcfg bridge

test: $(VENV)/.stamp ## Run tests
	$(VENV_BIN)/pytest

lint: $(VENV)/.stamp ## Run linter
	$(VENV_BIN)/ruff check src/ tests/

INSTALL_DIR := /opt/gdoc2netcfg

install: ## Install into /opt/gdoc2netcfg
	uv venv $(INSTALL_DIR)
	uv pip install --python $(INSTALL_DIR)/bin/python .

clean: ## Remove generated output
	rm -rf $(OUTPUT_DIR)

dist-clean: clean ## Remove generated output and virtualenv
	rm -rf $(VENV)

.PHONY: help setup run generate fetch scan test lint install clean dist-clean
