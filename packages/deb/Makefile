SUBDIRS := $(shell find debian/* -maxdepth 0 -type d ! -name DEBIAN)
PKG_NAME := libnftnl
GIT_LAST_TAG := $(shell git tag |tail -n 1 |cut -d "-" -f 2)
VERSION := $(or ${STRIPPED_VERSION},$(shell git describe --tags --exact-match 2> /dev/null | cut -d "-" -f 2))

ifeq ($(strip $(VERSION)),)
	VERSION=$(GIT_LAST_TAG)-$(shell git symbolic-ref -q --short HEAD || git rev-parse --short HEAD)
endif


.PHONY: all install clean install_deb

all:

install:

install_deb:
	fpm \
	-s dir -t deb \
	-p $(PKG_NAME)-$(VERSION)-any.deb \
	--name $(PKG_NAME) \
	--version $(VERSION) \
	--architecture all \
	--description "libnftnl library that support ndpi." \
	--maintainer "Kalashnikov V. kalashnikov.v24@wb.ru" \
	./debian/opt/hbf=/opt/

clean:
	rm -rf *.deb
	rm -rf $(SUBDIRS)

distclean: clean
