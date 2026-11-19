# ITShield Antivirus - RPM spec file
# Build with: rpmbuild -bb deploy/itshield.spec (after `make build-rpm`)

Name:       itshield-antivirus
Version:    VERSION
Release:    1%{?dist}
Summary:    ITShield Antivirus - Endpoint Protection Platform
License:    Proprietary
URL:        https://github.com/your-org/itshield-antivirus
Source0:    %{name}-%{version}.tar.gz
BuildArch:  noarch

Requires:   python3 >= 3.10
Requires:   python3-pip
Requires:   yara
Recommends: python3-PySide6
Recommends: python3-inotify_simple
Recommends: python3-cryptography

%description
ITShield Antivirus is a modular antivirus + EDR framework for Linux with:
hash, signature, YARA, and PE-based malware detection; real-time file
protection (inotify); process and network monitoring; quarantine engine;
correlation engine for incident detection; behavior analyzer; 12 curated
YARA rule sources; abuse.ch IOC feeds; Ed25519 signed updates; sandbox
analyzer; full RTL GUI with system tray; HTML/JSON reporting; systemd
service integration.

%prep
%setup -q

%build
# Nothing to compile (pure Python).

%install
mkdir -p %{buildroot}/opt/itshield
mkdir -p %{buildroot}/etc/systemd/system
mkdir -p %{buildroot}/usr/bin

cp -r itshield signatures rules test_scanner.py pyproject.toml README.md %{buildroot}/opt/itshield/
cp deploy/itshield.service %{buildroot}/etc/systemd/system/

# Wrapper script.
cat > %{buildroot}/usr/bin/itshield << 'EOF'
#!/bin/bash
cd /opt/itshield && python3 -m itshield.cli "$@"
EOF
chmod 755 %{buildroot}/usr/bin/itshield

# GUI wrapper.
cat > %{buildroot}/usr/bin/itshield-gui << 'EOF'
#!/bin/bash
cd /opt/itshield && python3 -m itshield.gui.main "$@"
EOF
chmod 755 %{buildroot}/usr/bin/itshield-gui

%pre
# Stop the service before upgrade.
systemctl stop itshield.service 2>/dev/null || true

%post
# Create system user.
if ! id itshield &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin itshield
fi

# Create data directories.
mkdir -p /var/lib/itshield /var/log/itshield /run/itshield
mkdir -p /opt/itshield/data/quarantine /opt/itshield/data/bank_backups /opt/itshield/reports
chown -R itshield:itshield /var/lib/itshield /var/log/itshield /run/itshield /opt/itshield/data /opt/itshield/reports
chmod 700 /opt/itshield/data/quarantine

# Install Python dependencies.
pip3 install protobuf yara-python grpcio-tools inotify_simple cryptography 2>/dev/null || true

# Compile protobuf bindings if missing.
if [ ! -f /opt/itshield/itshield/ipc/protocol_pb2.py ]; then
    cd /opt/itshield
    python3 -m grpc_tools.protoc --proto_path=itshield/ipc --python_out=itshield/ipc itshield/ipc/protocol.proto
fi

systemctl daemon-reload
systemctl enable itshield.service 2>/dev/null || true

%preun
systemctl stop itshield.service 2>/dev/null || true
systemctl disable itshield.service 2>/dev/null || true

%postun
if [ $1 -eq 0 ]; then
    # Complete removal.
    userdel itshield 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
fi

%files
/opt/itshield/
/etc/systemd/system/itshield.service
/usr/bin/itshield
/usr/bin/itshield-gui

%changelog
* Mon Nov 17 2026 ITShield Team - 0.9.0-1
- Phase 13: IOC Matcher + Sandbox Analyzer
- Phase 12: 12 YARA sources + 3 IOC feeds
- Phase 11: Ed25519 signed updates + advanced behavior rules
- Phase 10: MalwareBazaar + Reporting + systemd
- Phase 9: YARA rule downloader from GitHub
- Phase 8: Update System + PE imports + C2 detection
- Phase 7: Correlation Engine + Behavior Analyzer + GUI
- Phase 6: Quarantine + Real-Time + Risk Engine
- Phase 5: Scanner Engine
- Phase 4: IPC
- Phase 3: Core + Event Bus + Storage
- Initial release
