SUBDIRS := $(shell find debian/* -maxdepth 0 -type d ! -name DEBIAN)
PKG_NAME := swarm-libnftnl
GIT_LAST_TAG := $(shell git tag |tail -n 1 |cut -d "-" -f 2)
VERSION := $(or ${STRIPPED_VERSION},$(shell git describe --tags --exact-match 2> /dev/null | cut -d "-" -f 2))

LD_CONF_DIR := $(CURDIR)/debian/etc/ld.so.conf.d/
LIB_DIR := $(CURDIR)/debian/opt/swarm
LD_CONF_FILE := $(CURDIR)/swarm.conf

ifeq ($(strip $(VERSION)),)
	VERSION=$(GIT_LAST_TAG)-$(shell git symbolic-ref -q --short HEAD || git rev-parse --short HEAD)
endif


.PHONY: all install clean install_deb

all:

install:

install_deb:
	mkdir -p $(LD_CONF_DIR)
	install -v $(LD_CONF_FILE) $(LD_CONF_DIR)
	fpm \
	-s dir -t deb \
	-p $(PKG_NAME)-$(VERSION)-any.deb \
	--name $(PKG_NAME) \
	--version $(VERSION) \
	--architecture all \
	--description "libnftnl library that support ndpi." \
	--maintainer "Kalashnikov V. kalashnikov.v24@wb.ru" \
	--after-install ./after-install.sh \
	$(LIB_DIR)=/opt/ \
	$(LD_CONF_DIR)=/etc/ld.so.conf.d/

clean:
	rm -rf *.deb
	rm -rf $(SUBDIRS)

distclean: clean
