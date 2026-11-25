.PHONY: help sync test e2e check wheel lab clean
.DEFAULT_GOAL := help

VENV := .venv/bin/python

help:
	@echo "android-renef-mcp — local development targets"
	@echo "  sync   install dependencies with uv"
	@echo "  test   offline unit tests (tests/ is gitignored; needs a local checkout)"
	@echo "  e2e    45-check device suite (needs adb + renef_server)"
	@echo "  check  compileall + unit tests"
	@echo "  wheel  build the sdist and wheel into dist/"
	@echo "  lab    run one Frida_Labs verification: make lab N=0x4"
	@echo "  clean  remove build artifacts and caches"

sync:
	uv sync

test: sync
	@if [ ! -d tests ]; then echo "no local tests/ (gitignored) - nothing to run"; exit 0; fi
	@$(VENV) -m unittest discover -s tests -p "test_*.py"

e2e: sync
	@if [ ! -f tests/test_e2e.py ]; then echo "no local tests/test_e2e.py (gitignored) - nothing to run"; exit 0; fi
	@adb devices | grep -q "device$$" || { echo "no adb device connected"; exit 1; }
	@$(VENV) tests/test_e2e.py

check: sync
	@$(VENV) -m compileall -q renef_mcp
	@echo "compileall OK"
	@$(MAKE) --no-print-directory test

wheel: sync
	uv build

lab: sync
	@if [ ! -f tests/verify_lab.py ]; then echo "no local tests/verify_lab.py (gitignored)"; exit 1; fi
	@if [ -z "$(N)" ]; then echo "usage: make lab N=0x4   (0x1..0xB)"; exit 1; fi
	@$(VENV) tests/verify_lab.py $(N)

clean:
	rm -rf dist build .pytest_cache .ruff_cache
	@find . -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
	@echo "cleaned"
