Name: libfastcommon
Version: 1.0.6
Release: 1%{?dist}
Summary: c common functions library extracted from my open source projects FastDFS
License: GPL
Group: Arch/Tech
URL:  http://github.com/happyfish100/libfastcommon/
Source: http://github.com/happyfish100/libfastcommon/

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n) 

#Requires: /sbin/chkconfig
#Requires: sh-utils textutils grep fileutils /etc/cron.d
#BuildRequires: perl %{_includedir}/linux/if.h gettext
Requires: %__cp %__mv %__chmod %__grep %__mkdir %__install %__id



%description
c common functions library extracted from my open source projects FastDFS.
this library is very simple and stable. functions including: string, logger,
chain, hash, socket, ini file reader, base64 encode / decode,
url encode / decode, fasttimer etc. 

%package devel
Summary: Development header file
Requires: %{name}%{?_isa} = %{version}-%{release}

%description devel
This pakcage provides the header files of libfastcommon


%prep
%setup -q

%build
# FIXME: I need to fix the upstream Makefile to use LIBDIR et al. properly and
# send the upstream maintainer a patch.
# add DOCDIR to the configure part
./make.sh

%install
rm -rf %{buildroot}
DESTDIR=$RPM_BUILD_ROOT ./make.sh install
#make install IGNORE_MAN_GROUP=y DOC_DIR=%{_docdir}/%{name}-%{version} INIT_DIR=%{_initrddir}

#install -m 0644 sysstat.crond %{buildroot}/%{_sysconfdir}/cron.d/sysstat

#%find_lang %{name}

%post
ln -fs /usr/local/lib/libfastcommon.so.1 %{_libdir}/libfastcommon.so
/sbin/ldconfig

%preun

%postun
rm -f %{_libdir}/libfastcommon.so
/sbin/ldconfig

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
/usr/local/lib/libfastcommon.so*
#/usr/local/include/*
#%{_libdir}/libfastcommon.*
%files devel
%defattr(-,root,root,-)
/usr/local/include/*

%changelog
* Mon Jun 23 2014  Zaixue Liao <liaozaixue@yongche.com>
- first RPM release (1.0)
