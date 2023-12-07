SUBDIRS := $(shell find debian/* -maxdepth 0 -type d ! -name DEBIAN)
PKG_NAME := libnftnl
PKG_VER := $(shell git tag |tail -n 1 |cut -d "-" -f 2)


.PHONY: all install clean install_deb

all:

install:

install_deb:
	dpkg-deb --build debian $(PKG_NAME)-$(PKG_VER).deb || exit 1

clean:
	rm -rf *.deb
	rm -rf $(SUBDIRS)

distclean: clean
