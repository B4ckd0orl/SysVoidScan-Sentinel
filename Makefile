.PHONY: install dev test lint docker-build docker-run clean scan help

PYTHON ?= python3
PIP ?= $(PYTHON) -m pip
PYTEST ?= $(PYTHON) -m pytest
DOCKER_IMAGE ?= sysvoidscan
DOCKER_TAG ?= latest

help:
	@echo "SysVoidScan Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make install        Install dependencies"
	@echo "  make dev            Install in development mode"
	@echo "  make test           Run tests"
	@echo "  make lint           Run linter"
	@echo "  make docker-build   Build Docker image"
	@echo "  make docker-run     Run in Docker"
	@echo "  make clean          Remove build artifacts"
	@echo "  make scan           Run a scan (SCAN_TARGET required)"
	@echo ""
	@echo "Examples:"
	@echo "  make scan SCAN_TARGET=http://example.com"
	@echo "  make docker-run SCAN_TARGET=http://example.com"

install:
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	$(PIP) install pytest pytest-cov

dev:
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	$(PIP) install -e .
	$(PIP) install pytest pytest-cov flake8

test:
	$(PYTEST) tests/ -v --tb=short

test-coverage:
	$(PYTEST) tests/ -v --tb=short --cov=. --cov-report=term-missing

lint:
	$(PYTHON) -m flake8 core/ modules/ tools/ reports/ --max-line-length=120 --ignore=E501,W503,E402

docker-build:
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

docker-run:
ifdef SCAN_TARGET
	docker run --rm -v $(PWD)/reports:/opt/sysvoidscan/reports $(DOCKER_IMAGE):$(DOCKER_TAG) python3 main.py -t $(SCAN_TARGET)
else
	@echo "Error: SCAN_TARGET is required."
	@echo "Usage: make docker-run SCAN_TARGET=http://example.com"
	@exit 1
endif

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ .eggs/ .coverage htmlcov/ reports/*.db reports/*.json

scan:
ifdef SCAN_TARGET
	$(PYTHON) main.py -t $(SCAN_TARGET)
else
	@echo "Error: SCAN_TARGET is required."
	@echo "Usage: make scan SCAN_TARGET=http://example.com"
	@exit 1
endif
