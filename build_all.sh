#!/bin/bash
# Build script for srtp_decoder for OS X and Linux
# v0.1

BUILD_PREFIX=`pwd`'/.usr'

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

test -d ${BUILD_PREFIX} && rm -fR ${BUILD_PREFIX}
mkdir ${BUILD_PREFIX}
echo "Prefix: ${BUILD_PREFIX}"

build_docopt
build_libsrtp

test -d .build && rm -fR .build
mkdir .build
cd .build
cmake ..
make

echo "Build completed, you can find srtp_decoder into .build"
