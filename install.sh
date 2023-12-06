#!/bin/bash

PKG_DIR=$(pwd)/packages/deb
INSTALL_DIR=$PKG_DIR/debian/opt/hbf/

function clean() {
  make clean
  make distclean
}

function configure() {
  ./autogen.sh
  ./configure --prefix=$INSTALL_DIR --program-prefix=/opt/hbf/
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