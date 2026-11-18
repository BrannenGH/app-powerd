%{!?pkg_version: %global pkg_version 0.0.0}
%{!?pkg_release: %global pkg_release 0}

%global debug_package %{nil}

%{!?_userunitdir: %global _userunitdir %{_prefix}/lib/systemd/user}

Name:           app-powerd
Version:        %{pkg_version}
Release:        %{pkg_release}.kde%{?dist}
Summary:        Saves battery by freezing or throttling unfocused GUI apps
License:        MIT
URL:            https://github.com/BrannenGH/app-powerd
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc

%description
app-powerd is a user-level daemon that saves battery by automatically
freezing or throttling background GUI applications through cgroup v2.

%prep
%autosetup -n %{name}-%{version}

%build
cargo build --release --locked --features wayland --bin app-powerd

%install
install -Dpm 0755 "${CARGO_TARGET_DIR:-target}/release/app-powerd" %{buildroot}%{_bindir}/app-powerd
sed -e 's|^ExecStart=.*|ExecStart=%{_bindir}/app-powerd run|' \
    -e 's|^Documentation=.*|Documentation=%{url}|' \
    dist/app-powerd.service > app-powerd.service
install -Dpm 0644 app-powerd.service %{buildroot}%{_userunitdir}/app-powerd.service
install -Dpm 0644 config/default.yaml %{buildroot}%{_sysconfdir}/app-powerd/config.yaml

%check
"%{buildroot}%{_bindir}/app-powerd" --version

%files
%license LICENSE
%doc README.md config/default.yaml
%dir %{_sysconfdir}/app-powerd
%config(noreplace) %{_sysconfdir}/app-powerd/config.yaml
%{_bindir}/app-powerd
%{_userunitdir}/app-powerd.service

%changelog
* Wed Nov 18 2026 Brannen Hall - 2.0.3-1.kde
- Install the default config as /etc/app-powerd/config.yaml

* Mon Nov 16 2026 Brannen Hall - 1.2.0-1.kde
- Package the KDE-enabled fork for repo.hallb.me
