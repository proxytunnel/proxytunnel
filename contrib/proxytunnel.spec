Summary: Proxy Tunnel ssh-over-https hack.
Name: proxytunnel
Version: 1.2.3
Release: 0.1
Copyright: GPL
Group: Networking/Utilities
Source0: http://prdownloads.sourceforge.net/proxytunnel/proxytunnel-%{version}.tgz
BuildRoot: %{_tmppath}/%{name}-root

%description
Proxytunnel is a program that connects stdin and stdout to an origin server
somewhere in the Internet through an industry standard HTTPS proxy. This will
allow you for example to access SSH servers when you normally only have access
to websites through a

%prep
%setup -n proxytunnel

%build

make CFLAGS="-O2"

%install
mkdir -p ${RPM_BUILD_ROOT}/usr/bin/
mkdir -p ${RPM_BUILD_ROOT}/usr/share/doc/proxytunnel/
install -m755 proxytunnel ${RPM_BUILD_ROOT}/usr/bin/
install -m644 README ${RPM_BUILD_ROOT}/usr/share/doc/proxytunnel/README.txt

%clean
rm -rf ${RPM_BUILD_ROOT}/usr/

%files
%defattr(-,root,root)
/usr/bin/proxytunnel
/usr/share/doc/proxytunnel/README.txt

%changelog
# Tue Nov  2  2004 Mark Janssen <maniac@maniac.nl>
- Updated to v1.2.3
* Tue Nov 21  2001 Ralph Loader <suckfish@ihug.co.nz>
- Created.
