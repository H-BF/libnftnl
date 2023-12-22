#!/bin/bash

PKG_DIR=$(pwd)/packages/deb
INSTALL_DIR=$PKG_DIR/debian/opt/swarm/

function clean() {
  make clean
  make distclean
}

function configure() {
  ./autogen.sh
  ./configure --prefix=$INSTALL_DIR --with-pkgdst=/opt/swarm
}

function build() {
  make all
  make install
  make -C $PKG_DIR install_deb
}

clean
set -e
configure
build

echo "Build successful! Check: $PKG_DIR"
