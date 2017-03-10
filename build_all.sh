#!/bin/bash
# Build script for srtp_decoder
# v0.1

function build_docopt() {
    cd docopt
    test -d .build && rm -fR .build
    mkdir .build
    cd .build
    cmake -DCMAKE_INSTALL_PREFIX=${BUILD_PREFIX} ..
    make && make install
    cd ../..
}

function build_libsrtp() {
    cd libsrtp
    ./configure --prefix=${BUILD_PREFIX} #--with-openssl-dir=/usr/local/opt/openssl/
    make && make install
    cd ..
}

test -d .build_usr && rm -fR .build_usr
mkdir .build_usr
BUILD_PREFIX=`pwd`'/.build_usr'
echo "Prefix: ${BUILD_PREFIX}"

build_docopt
build_libsrtp

test -d .build && rm -fR .build
mkdir .build
cd .build
cmake ..
make

echo "Build completed"
