%define __spec_install_post %{nil}
%define __os_install_post %{_dbpath}/brp-compress
%define debug_package %{nil}

Name: innernet-server
Summary: A server to coordinate innernet networks.
Version: @@VERSION@@
Release: @@RELEASE@@%{?dist}
License: MIT
Source0: %{name}-%{version}.tar.gz
URL: https://github.com/tonarino/innernet

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

Requires: glibc
Requires: systemd
Requires: libgcc
Requires: sqlite
Requires: zlib

%description
%{summary}

%prep
%setup -q

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a * %{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_bindir}/*
%attr(0644, root, root) "/usr/lib/systemd/system/innernet-server@.service"
%attr(0644, root, root) "/usr/share/man/man8/innernet-server.8.gz"
