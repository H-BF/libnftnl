SUBDIRS := $(shell find debian/* -maxdepth 0 -type d ! -name DEBIAN)
PKG_NAME := libnftnl
PKG_VER := $(shell git tag |tail -n 1 |cut -d "-" -f 2)


.PHONY: all install clean install_deb

all:

install:

install_deb:
	fpm \
	-s dir -t deb \
	-p libnftnl-$(STRIPPED_VERSION)-any.deb \
	--name libnftnl \
	--version $(STRIPPED_VERSION) \
	--architecture all \
	--description "libnftnl library that support ndpi." \
	--maintainer "Kalashnikov V. kalashnikov.v24@wb.ru" \
	./debian/opt/hbf=/opt/

clean:
	rm -rf *.deb
	rm -rf $(SUBDIRS)

distclean: clean
