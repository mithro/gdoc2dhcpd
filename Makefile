VENV := .venv
VENV_BIN := $(VENV)/bin

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

fetch: $(VENV)/.stamp ## Download CSVs from Google Sheets
	$(VENV_BIN)/gdoc2netcfg fetch

test: $(VENV)/.stamp ## Run tests
	$(VENV_BIN)/pytest

lint: $(VENV)/.stamp ## Run linter
	$(VENV_BIN)/ruff check src/ tests/

INSTALL_DIR := /opt/gdoc2netcfg

install: ## Install into /opt/gdoc2netcfg
	uv venv $(INSTALL_DIR)
	uv pip install --python $(INSTALL_DIR)/bin/python .

clean: ## Remove local development virtualenv
	rm -rf $(VENV)

.PHONY: help setup run fetch test lint install clean
