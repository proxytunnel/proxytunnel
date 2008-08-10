# $Id$
# Authority: dag
# Upstream: <proxytunnel-users$lists,sourceforge,net>

Summary: Punching holes through HTTPS proxies
Name: proxytunnel
Version: 1.9.0
Release: 1
License: GPL
Group: Applications/Internet
URL: http://proxytunnel.sourceforge.net/

Source: http://dl.sf.net/proxytunnel/proxytunnel-%{version}.tgz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

BuildRequires: openssl-devel

%description
ProxyTunnel is a program that connects stdin and stdout to a server somewhere
on the network, through a standard HTTPS proxy. We mostly use it to tunnel
SSH sessions through HTTP(S) proxies, allowing us to do many things that
wouldn't be possible without ProxyTunnel.

Proxytunnel can create tunnels using HTTP and HTTPS proxies, can work as a
back-end driver for an OpenSSH client, and create SSH connections through
HTTP(S) proxies and can work as a stand-alone application, listening on a
port for connections, and then tunneling these connections to a specified
destination.

If you want to make effective use of ProxyTunnel, the proxy server you are
going to be tunneling through must support HTTP CONNECT command and must
allow you to connect to destination machine and host, with or without HTTP
proxy authentication.

%prep
%setup

%build
%{__make} %{?_smp_mflags} CFLAGS="%{optflags} -I/usr/kerberos/include"

%install
%{__rm} -rf %{buildroot}
%{__make} install DESTDIR="%{buildroot}" PREFIX="%{_prefix}"

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-, root, root, 0755)
%doc CHANGES CREDITS INSTALL KNOWN_ISSUES LICENSE.txt README REL_NOTES TODO docs/*.txt docs/*.html
%doc %{_mandir}/man1/proxytunnel.1*
%{_bindir}/proxytunnel

%changelog
* Fri Jan 18 2008 Dag Wieers <dag@wieers.com> - 1.8.0-1
- Updated to release 1.8.0.

* Fri Mar 16 2007 Dag Wieers <dag@wieers.com> - 1.7.0-1
- Updated to release 1.7.0.

* Sun Aug 06 2006 Dag Wieers <dag@wieers.com> - 1.6.3-1
- Updated to release 1.6.3.

* Tue Nov  2  2004 Mark Janssen <maniac@maniac.nl>
- Updated to v1.6.0

* Tue Nov 21  2001 Ralph Loader <suckfish@ihug.co.nz>
- Created.
