LIB_DIR=$(CURDIR)/../content/
LD_CONF_FILE=$(CURDIR)/swarm.conf

if BUILD_RPM
build-rpm:
	fpm \
	-s dir -t rpm \
	-p $(PKG_NAME)-$(PKG_VERSION)-any.rpm \
	--name $(PKG_NAME) \
	--version $(PKG_VERSION) \
	--architecture all \
	--description "libnftnl library that support ndpi." \
	--maintainer "Kalashnikov V. kalashnikov.v24@wb.ru" \
	--after-install ./after-install.sh \
	$(LIB_DIR)=$(pkgdst) \
	$(LD_CONF_FILE)=/etc/ld.so.conf.d/

clean-rpm:
	rm -rf *.rpm

endif

