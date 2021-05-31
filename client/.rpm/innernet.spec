%define __spec_install_post %{nil}
%define __os_install_post %{_dbpath}/brp-compress
%define debug_package %{nil}

Name: innernet
Summary: A client to manage innernet network interfaces.
Version: @@VERSION@@
Release: @@RELEASE@@%{?dist}
License: MIT
Source0: %{name}-%{version}.tar.gz
URL: https://github.com/tonarino/innernet

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

Requires: glibc
Requires: systemd
Requires: libgcc

%description
%{summary}

%prep
%setup -q

%build
ln -s %{name} .%{_bindir}/inn

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a * %{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_bindir}/*
%attr(0644, root, root) "/usr/lib/systemd/system/innernet@.service"
%attr(0644, root, root) "/usr/share/man/man8/innernet.8.gz"
%attr(0644, root, root) "/etc/bash_completion.d/innernet"
%attr(0644, root, root) "/usr/share/fish/vendor_completions.d/innernet.fish"
%attr(0644, root, root) "/usr/share/zsh/site-functions/_innernet"
