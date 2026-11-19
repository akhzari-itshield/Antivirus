# ITShield Antivirus - Dockerfile
# Multi-stage build: install dependencies, then copy the project.
#
# Build:   docker build -t itshield-antivirus:latest .
# Run:     docker run --rm -it -v $(pwd)/data:/opt/itshield/data itshield-antivirus:latest
# Shell:   docker run --rm -it -v $(pwd)/data:/opt/itshield/data itshield-antivirus:latest /bin/bash

FROM python:3.12-slim AS base

# System dependencies: libyara for yara-python, libGL/EGL for PySide6.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libyara-dev \
        build-essential \
        libgl1 \
        libegl1 \
        libxkbcommon0 \
        libdbus-1-3 \
        inotify-tools \
        procps \
        && rm -rf /var/lib/apt/lists/*

# Python dependencies.
RUN pip install --no-cache-dir \
        protobuf>=4.25 \
        yara-python>=4.3 \
        grpcio-tools \
        inotify-simple>=2.0 \
        cryptography>=42.0 \
        pytest>=8.0

# Create the itshield user.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin itshield

# Copy the project.
WORKDIR /opt/itshield
COPY --chown=itshield:itshield itshield/ ./itshield/
COPY --chown=itshield:itshield signatures/ ./signatures/
COPY --chown=itshield:itshield rules/ ./rules/
COPY --chown=itshield:itshield test_scanner.py pyproject.toml README.md ./
COPY deploy/itshield.service /etc/systemd/system/

# Compile protobuf bindings.
RUN python -m grpc_tools.protoc \
        --proto_path=itshield/ipc \
        --python_out=itshield/ipc \
        itshield/ipc/protocol.proto

# Create runtime directories.
RUN mkdir -p /opt/itshield/data/quarantine \
             /opt/itshield/data/bank_backups \
             /opt/itshield/reports \
             /var/lib/itshield \
             /var/log/itshield \
             /run/itshield \
    && chown -R itshield:itshield /opt/itshield /var/lib/itshield /var/log/itshield /run/itshield \
    && chmod 700 /opt/itshield/data/quarantine

# Default environment.
ENV PYTHONPATH=/opt/itshield
ENV PYTHONUNBUFFERED=1
ENV ITSHIELD_IPC_SOCKET=/run/itshield/itshield.sock

# Default command: run the CLI help.
USER itshield
ENTRYPOINT ["python", "-m", "itshield.cli"]
CMD ["--help"]
