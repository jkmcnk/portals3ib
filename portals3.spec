#
# portals 3.4.0 ibng spec file
#
Summary: Portals 3 communication library.
Name: portals3
Version: 3.4.0
Release: 1
License: GPL
Group: Development/Libraries
URL: TODO
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Vendor: NEC
Packager: Jaka Mocnik <jaka@xlab.si>

%description
An implementation of the Portals 3 communication API specification with
an Infiniband NAL.

%package -n portals3-test
Summary: Portals 3 test applicaitons.
Group: Development/Libraries
%description -n portals3-test
Test applications for the Portals 3 library.

%package -n libportals3
Summary: The Portals 3 libraries.
Group: Development/Libraries
%description -n libportals3
An implementation of the Portals 3 communication API specification with
an Infiniband NAL.

%package -n libportals3-devel
Summary: The Portals 3 header files and static libraries.
Group: Development/Libraries
Requires: libportals3
%description -n libportals3-devel
Development files for the Portals 3 communication API specification with
an Infiniband NAL.

%prep
%setup -q

%build
./configure --prefix=/usr --libdir=/usr/lib64 --enable-ibng-nal \
            --with-ibng-connection-method=CMA --enable-threaded-library \
            --enable-tests --disable-lib-debug --disable-lib-profile \
            --enable-shared --enable-static --disable-runtime-support
make

%install
make DESTDIR=$RPM_BUILD_ROOT install
rm -rf $RPM_BUILD_ROOT/usr/include/p3rt
rm -f $RPM_BUILD_ROOT/usr/include/p3nal_utcp.h

%clean
rm -rf $RPM_BUILD_ROOT

%files -n portals3-test
%defattr(-, root, root -)
/usr/bin

%files -n libportals3
%defattr(-, root, root -)
/usr/lib64/libportals3.so.0
/usr/lib64/libportals3.so.0.0.0
/usr/lib64/libportals3-ibng.so.0
/usr/lib64/libportals3-ibng.so.0.0.0
%doc /usr/share/doc/portals3/AUTHORS
%doc /usr/share/doc/portals3/COPYING
%doc /usr/share/doc/portals3/README
%doc /usr/share/doc/portals3/README.limitations
%doc /usr/share/doc/portals3/README.nals
%doc /usr/share/doc/portals3/nal/ibng/README

%files -n libportals3-devel
%defattr(-, root, root -)
/usr/lib64/libportals3.so
/usr/lib64/libportals3-ibng.so
/usr/lib64/libportals3.la
/usr/lib64/libportals3-ibng.la
/usr/lib64/libportals3.a
/usr/lib64/libportals3-ibng.a
/usr/lib64/pkgconfig/portals3.pc
/usr/include/p3
/usr/include/p3api
/usr/include/p3nal_ibng.h
/usr/include/portals3.h

%changelog
* Fri Apr  8 2011  <jaka@xlab.si> -
- Initial packaging.
