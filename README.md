# LIBNFTNL WITH nDPI SUPPORT
This is a fork of the official [libnftnl](https://git.netfilter.org/libnftnl/) library extended to support [nDPI](https://gitlab-internal.wildberries.ru/swarm/swarm/ndpi) netfilter kernel module based on a fork from the [netfilter ndpi](https://github.com/vel21ripn/nDPI).

This library implements an additional netlink interface for connecting to the [ndpi kernel module](https://gitlab-internal.wildberries.ru/swarm/swarm/ndpi)

## How To Compile
### Prerequisites:
  - build tooling: glibc headers, gcc, autotools, automake, libtool.

  - optional: asciidoc: required for building man-page

  - optional: [fpm](https://fpm.readthedocs.io/en/v1.15.1/index.html): required for building deb or rpm packages

### Configuring and compiling
 - Run "sh autogen.sh" to generate the configure script

 - ./configure [options]

    --prefix=

        The prefix to put all installed files under. It defaults to
        /usr/local, so the binaries will go into /usr/local/bin, sbin,
        manpages into /usr/local/share/man, etc.

    --datarootdir=

	    The base directory for arch-independent files. Defaults to
	    $prefix/share.

    --with-build-deb

	    To enable build with deb package

    --with-build-rpm

	    To enable build with rpm package

    --with-pkgdst=

	    Path where the package will be installed. By default all will be installed into path determinated by the --prefix option

 - Run "make" to compile libnftnl.
 - Run "make install" to install it in the configured paths.


### Configuration with package
 To enable build a package just configure one of the option:

	./configure --with-build-deb
	make build-deb
	or
	./configure --with-build-rpm
	make build-rpm
 If you need to install a package to a specific location
 you have to specify the path using the --with-pkgdst option:

	./configure --with-pkgdst=/opt/swarm/ --with-build-deb
	make build-deb
