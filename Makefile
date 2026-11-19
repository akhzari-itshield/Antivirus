# ITShield Antivirus - Makefile
# Common development operations.
#
# Usage:
#   make help          - show available targets
#   make test          - run pytest suite
#   make install       - pip install in development mode
#   make build-deb     - build a .deb package
#   make build-rpm     - build an RPM package (requires rpmbuild)
#   make docker-build  - build the Docker image
#   make clean         - remove build artifacts
#   make benchmark     - run scan performance benchmark

PYTHON ?= python3
PIP ?= pip3
PROJECT := itshield-antivirus
VERSION := $(shell $(PYTHON) -c "import itshield; print(itshield.__version__)" 2>/dev/null || echo "0.0.0")

.PHONY: help test install dev-install clean build-deb build-rpm docker-build docker-run benchmark proto lint

help:  ## Show this help
	@echo "ITShield Antivirus - Makefile (v$(VERSION))"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

test:  ## Run the pytest test suite
	$(PYTHON) -m pytest tests/ -v

test-fast:  ## Run tests without verbose output
	$(PYTHON) -m pytest tests/ -q

test-cov:  ## Run tests with coverage report
	$(PYTHON) -m pytest tests/ --cov=itshield --cov-report=term-missing

install:  ## Install the package (pip install -e .)
	$(PIP) install -e .

dev-install:  ## Install with dev dependencies
	$(PIP) install -e ".[dev]"

proto:  ## Regenerate the Protobuf Python bindings
	$(PYTHON) -m grpc_tools.protoc \
		--proto_path=itshield/ipc \
		--python_out=itshield/ipc \
		itshield/ipc/protocol.proto
	@echo "Protobuf bindings regenerated."

lint:  ## Run basic syntax checks on all Python files
	@find itshield tests -name '*.py' -exec $(PYTHON) -m py_compile {} + 2>&1 | head -20
	@echo "Syntax check complete."

benchmark:  ## Run scan performance benchmark
	$(PYTHON) -m itshield.cli scan /tmp --no-store

# ----------------------------------------------------------------- Debian package
build-deb:  ## Build a .deb package (requires dpkg-deb)
	@echo "Building .deb package for v$(VERSION)..."
	@rm -rf /tmp/itshield-deb
	@mkdir -p /tmp/itshield-deb/DEBIAN
	@mkdir -p /tmp/itshield-deb/opt/itshield
	@mkdir -p /tmp/itshield-deb/etc/systemd/system
	@mkdir -p /tmp/itshield-deb/usr/bin
	# Copy project files.
	@cp -r itshield signatures rules test_scanner.py pyproject.toml README.md /tmp/itshield-deb/opt/itshield/
	# Control file.
	@sed 's/VERSION/$(VERSION)/g' deploy/debian/control > /tmp/itshield-deb/DEBIAN/control
	@cp deploy/debian/postinst /tmp/itshield-deb/DEBIAN/postinst
	@cp deploy/debian/prerm /tmp/itshield-deb/DEBIAN/prerm
	@cp deploy/debian/postrm /tmp/itshield-deb/DEBIAN/postrm
	@chmod 755 /tmp/itshield-deb/DEBIAN/postinst /tmp/itshield-deb/DEBIAN/prerm /tmp/itshield-deb/DEBIAN/postrm
	# systemd service.
	@cp deploy/itshield.service /tmp/itshield-deb/etc/systemd/system/
	# Wrapper script.
	@echo '#!/bin/bash' > /tmp/itshield-deb/usr/bin/itshield
	@echo 'cd /opt/itshield && python3 -m itshield.cli "$$@"' >> /tmp/itshield-deb/usr/bin/itshield
	@chmod 755 /tmp/itshield-deb/usr/bin/itshield
	# Build.
	@dpkg-deb --build /tmp/itshield-deb "$(PROJECT)_$(VERSION)_all.deb"
	@echo "Built: $(PROJECT)_$(VERSION)_all.deb"
	@rm -rf /tmp/itshield-deb

# ----------------------------------------------------------------- RPM package
build-rpm:  ## Build an RPM package (requires rpmbuild)
	@echo "Building RPM package for v$(VERSION)..."
	@mkdir -p ~/rpmbuild/SPECS ~/rpmbuild/SOURCES
	@tar -czf ~/rpmbuild/SOURCES/$(PROJECT)-$(VERSION).tar.gz \
		--transform 's,^,$(PROJECT)-$(VERSION)/,' \
		itshield signatures rules test_scanner.py pyproject.toml README.md deploy
	@sed 's/VERSION/$(VERSION)/g' deploy/itshield.spec > ~/rpmbuild/SPECS/$(PROJECT).spec
	@rpmbuild -bb ~/rpmbuild/SPECS/$(PROJECT).spec
	@echo "RPM built in ~/rpmbuild/RPMS/noarch/"

# ----------------------------------------------------------------- Docker
docker-build:  ## Build the Docker image
	docker build -t $(PROJECT):$(VERSION) -t $(PROJECT):latest .

docker-run:  ## Run the Docker container
	docker run --rm -it \
		-v $(PWD)/data:/opt/itshield/data \
		-v $(PWD)/signatures:/opt/itshield/signatures \
		-v $(PWD)/rules:/opt/itshield/rules \
		$(PROJECT):latest

docker-shell:  ## Open a shell in the Docker container
	docker run --rm -it \
		-v $(PWD)/data:/opt/itshield/data \
		$(PROJECT):latest /bin/bash

# ----------------------------------------------------------------- Cleanup
clean:  ## Remove build artifacts and cache files
	@find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -delete 2>/dev/null || true
	@rm -rf .pytest_cache tests/.pytest_cache htmlcov .coverage
	@rm -rf build dist *.egg-info
	@rm -f *.deb *.rpm
	@rm -rf /tmp/itshield-deb
	@echo "Cleaned."

distclean: clean  ## Deep clean - also remove data/reports directories
	@rm -rf data/* reports/*
	@echo "Distribution cleaned."
