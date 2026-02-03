VENV := .venv
VENV_BIN := $(VENV)/bin

# Create venv and install project with dev dependencies.
# Re-runs when pyproject.toml or uv.lock change.
$(VENV)/.stamp: pyproject.toml uv.lock
	uv sync --dev
	touch $@

setup: $(VENV)/.stamp

test: $(VENV)/.stamp
	$(VENV_BIN)/pytest

lint: $(VENV)/.stamp
	$(VENV_BIN)/ruff check src/ tests/

INSTALL_DIR := /opt/gdoc2netcfg

install:
	uv venv $(INSTALL_DIR)
	uv pip install --python $(INSTALL_DIR)/bin/python .

clean:
	rm -rf $(VENV)

.PHONY: setup test lint install clean
