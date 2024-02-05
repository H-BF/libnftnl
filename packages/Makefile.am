if BUILD_DEB
build-deb:
	$(MAKE) -C ./deb build-deb
clean-deb:
	$(MAKE) -C ./deb clean-deb
	rm -rf ./content/*
endif

if BUILD_RPM
build-rpm:
	$(MAKE) -C ./rpm build-rpm
clean-rpm:
	$(MAKE) -C ./rpm clean-rpm
	rm -rf ./content/*
endif
