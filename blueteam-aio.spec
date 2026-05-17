# By🇭🇷PhonkAlphabet
Name:           blueteam-aio
Version:        1.3.0
Release:        1%{?dist}
Summary:        BlueTeam AIO - Production-Grade Security Platform
License:        MIT
URL:            https://github.com/masterfrequency/bluelinux
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
Requires:       python3, python3-psutil, yara, auditd, bcc-tools

%description
BlueTeam AIO is a complete cybersecurity platform with 21+ modules including
eBPF kernel monitoring, memory forensics, network defense, and AI integration.

%prep
%setup -q

%install
mkdir -p %{buildroot}/opt/blueteam-aio
mkdir -p %{buildroot}/etc/systemd/system
cp -r src %{buildroot}/opt/blueteam-aio/
cp -r plugins %{buildroot}/opt/blueteam-aio/
cp debian/blueteam-aio.service %{buildroot}/etc/systemd/system/

%files
/opt/blueteam-aio
/etc/systemd/system/blueteam-aio.service

%post
systemctl daemon-reload
systemctl enable blueteam-aio

%changelog
* Sun May 17 2026 BlueTeam Security <security@blueteam.io> - 1.3.0-1
- Initial RPM release for BlueTeam AIO Ultimate Edition
