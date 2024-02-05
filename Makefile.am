include $(top_srcdir)/Make_global.am

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src include examples tests
DIST_SUBDIRS = src include examples tests

if BUILD_DEB_OR_RPM
    SUBDIRS += packages
    DIST_SUBDIRS += packages
endif

if BUILD_DEB
SUBDIRS += packages/deb
DIST_SUBDIRS += packages/deb

build-deb: clean-deb install
	$(MAKE) -C packages build-deb
clean-deb:
	$(MAKE) -C packages clean-deb

endif

if BUILD_RPM
SUBDIRS += packages/rpm
DIST_SUBDIRS += packages/rpm

build-rpm: clean-rpm install
	$(MAKE) -C packages build-rpm
clean-rpm:
	$(MAKE) -C packages clean-rpm

endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libnftnl.pc
