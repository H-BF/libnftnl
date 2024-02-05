LIB_DIR=$(CURDIR)/../content/
LD_CONF_FILE=$(CURDIR)/swarm.conf

if BUILD_DEB
build-deb:
	fpm \
	-s dir -t deb \
	-p $(PKG_NAME)-$(PKG_VERSION)-any.deb \
	--name $(PKG_NAME) \
	--version $(PKG_VERSION) \
	--architecture all \
	--description "libnftnl library that support ndpi." \
	--maintainer "Kalashnikov V. kalashnikov.v24@wb.ru" \
	--after-install ./after-install.sh \
	$(LIB_DIR)=$(pkgdst) \
	$(LD_CONF_FILE)=/etc/ld.so.conf.d/

clean-deb:
	rm -rf *.deb

endif

