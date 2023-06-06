#!/usr/bin/env bash

set -e

THISDIR="$(dirname $(readlink -f $0))"

DEPSDIR="$THISDIR/deps"

ALL_COMPONENTS="libcurl cares grpc"
OPENSSLDIR=openssl
CURLDIR=curl
PROTOBUFDIR=protobuf
CARESDIR=cares
GRPCDIR=grpc

SHOW_HELP() {
    LOG_INFO "Usage: $0 [component-name]\n"
    LOG_INFO "Build component in [$ALL_COMPONENTS] or all by default\n"
    exit 0
}

LOG_DEBUG() {
    echo -e "\033[36m$@\033[0m"
}

LOG_INFO() {
    echo -e "\033[32m$@\033[0m"
}

LOG_ERROR() {
    echo -e "\033[31m$@\033[0m"
}

ERROR_EXIT() {
  LOG_ERROR "$@" && exit 1
}

TRYGET() {
    local dst=$1
    local url=$2
    local pkg=${3:-$(basename $url)}
    local flag="./occlum_demo_source"

    # Download package tarball
    if [ ! -e $pkg ] ; then
        LOG_DEBUG "Downloading $pkg ..."
        wget $url -O $pkg || ERROR_EXIT "Fail to download $pkg"
    else
        LOG_INFO "[READY] $pkg source package file"
    fi

    # Prepare the source code directory
    if [ ! -f $dst/$flag ] ; then
        LOG_DEBUG "Preparing source code: $dst ..."
        mkdir -p $dst && \
        tar -xvf $pkg -C $dst --strip-components 1 >/dev/null || \
        ERROR_EXIT "Fail to extract archive file $pkg"
        touch $dst/$flag && \
        LOG_DEBUG "Prepare $(basename $dst) source code successfully"
    else
        LOG_INFO "[READY] $dst source directory"
    fi
}

GITGET_GRPC() {
    GRPC_SRC_DIR=$DEPSDIR/$GRPCDIR
    if [ -d $GRPC_SRC_DIR/third_party/protobuf/cmake ] ; then
        LOG_INFO "[READY] grpc"
        return 0
    fi

    LOG_DEBUG "Preparing source code: grpc ..."
    #rm -rf $GRPC_SRC_DIR && \
    mkdir -p $GRPC_SRC_DIR && cd $GRPC_SRC_DIR
    git clone https://github.com/grpc/grpc.git .
    git checkout tags/v1.24.3
    #git submodule update --init --recursive
    cd $GRPC_SRC_DIR/third_party/cares/cares
    git submodule update --init .
    git checkout tags/cares-1_15_0
    cd $GRPC_SRC_DIR/third_party/protobuf
    git submodule update --init .
    git checkout tags/v3.21.6
    cd $GRPC_SRC_DIR/third_party/abseil-cpp
    git submodule update --init .
    return 0
}

openssl_check() {
    [ -f "$INSTALLDIR/lib/libcrypto.so.1.1" ] || \
    [ -f "$INSTALLDIR/lib/libcrypto.a" ] || \
    return 1
}

openssl_build() {
    cd "$DEPSDIR/$OPENSSLDIR" && \
    ./config --prefix=$INSTALLDIR \
      --openssldir=/usr/local/occlum/ssl \
      --with-rand-seed=rdcpu \
      no-zlib no-async no-tests enable-egd && \
    make -j$(nproc) && make install
}

libcurl_check() {
    [ -f "$INSTALLDIR/lib/libcurl.so" ] || \
    [ -f "$INSTALLDIR/lib/libcurl.a" ] || \
    return 1
}

libcurl_build() {
    cd "$DEPSDIR/$CURLDIR"
    if [ ! -f ./configure ] ; then
      LOG_DEBUG "Building configure file ..."
      ./buildconf || exit 1
    fi
    ./configure \
      --prefix=$INSTALLDIR \
      --with-openssl \
      --without-zlib && \
    make -j$(nproc) && make install

    # Rename static curl lib to force doing staticly link in next step
    cp $INSTALLDIR/lib/libcurl.a $INSTALLDIR/lib/libcurl_static.a
}

protobuf_check() {
    [ -f "$INSTALLDIR/lib/libprotobuf.so.32" ] || \
    [ -f "$INSTALLDIR/lib64/libprotobuf.so.32" ] || \
    return 1
}

protobuf_build() {
    echo "======== Building protobuf ... ========" && \
    cd $DEPSDIR/$GRPCDIR/third_party/protobuf/cmake && \
    rm -rf build && mkdir -p build && cd build && \
    cmake ../ \
        -DCMAKE_INSTALL_PREFIX=$INSTALLDIR \
        -Dprotobuf_BUILD_TESTS=OFF       \
        -DBUILD_SHARED_LIBS=TRUE         \
        -DCMAKE_CXX_FLAGS="-fPIC -pie"   \
        -DCMAKE_C_FLAGS="-fPIC -pie"     \
        -DCMAKE_BUILD_TYPE=Release &&    \
    make -j$(nproc) && \
    make install
    [ -f "$INSTALLDIR/lib/libprotobuf.so.32" ] || cp ./libprotobuf.so.32 $INSTALLDIR/lib/
}

cares_check() {
    [ -f "$INSTALLDIR/lib/libcares.so" ] || return 1
}

cares_build() {
    echo "======== Building cares ... ========" && \
    cd $DEPSDIR/$GRPCDIR/third_party/cares/cares/ && \
    rm -rf build && mkdir -p build && cd build && \
    cmake ../ \
        -DCMAKE_INSTALL_PREFIX=$INSTALLDIR \
        -DCARES_STATIC=ON \
        -DCMAKE_CXX_FLAGS="-fPIC -pie"   \
        -DCMAKE_C_FLAGS="-fPIC -pie"     \
	    -DCMAKE_BUILD_TYPE=Release &&    \
    make -j$(nproc) && \
    make install
}

grpc_check() {
    [ -f "$INSTALLDIR/lib/libgrpc.so" ] || \
    [ -f "$INSTALLDIR/lib/libgrpc.a" ] || \
    return 1
}

grpc_build() {
    echo "======== Building grpc ... ========" && \
    cd $DEPSDIR/$GRPCDIR/cmake && \
    rm -rf build && mkdir -p build && cd build && \
    export PROTOBUF_DIR=$INSTALLDIR
    cmake ../.. \
        -DCMAKE_INSTALL_PREFIX=$INSTALLDIR \
        -DgRPC_BUILD_TESTS=OFF           \
        -DgRPC_INSTALL=ON                \
        -DgRPC_CARES_PROVIDER=package    \
        -DgRPC_SSL_PROVIDER=package      \
        -DgRPC_ZLIB_PROVIDER=package     \
        -DCMAKE_CXX_FLAGS="-fPIC -pie"   \
        -DCMAKE_C_FLAGS="-fPIC -pie"     \
        -DCMAKE_BUILD_TYPE=Release &&    \
    make -j$(nproc) && \
    make install
    [ -f $INSTALLDIR/lib/libgrpc.a ] || cp ./lib*.a $INSTALLDIR/lib
    [ -f /usr/bin/grpc_cpp_plugin ] || cp ./grpc_cpp_plugin /usr/bin
}

# Show help menu
[ "$1" == "-h" -o "$1" == "--help" ] && SHOW_HELP

# Check the build mode
BUILDMODE="Release"
BUILDVERBOSE=""
if [ "$1" == "--debug" ] ; then
  BUILDMODE="Debug"
  BUILDVERBOSE="VERBOSE=1"
  shift;
fi

# Check the force build option
BUILDFORCE="NO"
if [ "$1" == "--force" ] ; then
  BUILDFORCE="YES"
  shift;
fi

# Check the occlum libc type and decide the compiler
PKGCONFIGPATH="/opt/occlum/toolchains/gcc/x86_64-linux-gnu/lib/pkgconfig"
INSTALLDIR="/opt/occlum/toolchains/gcc/x86_64-linux-gnu"
OCCLUMCC="gcc -fPIC -pie"
OCCLUMCXX="g++ -fPIC -pie"
if [ "$1" == "--libc" ] ; then
    if [ "$2" == "musl" ] ; then
        echo "Build with musl libc ..."
        INC_DIR_MUSL="/opt/occlum/toolchains/gcc/x86_64-linux-musl/include"
        PKGCONFIGPATH="/opt/occlum/toolchains/gcc/x86_64-linux-musl/lib/pkgconfig"
        INSTALLDIR="/opt/occlum/toolchains/gcc/x86_64-linux-musl"
        OCCLUMCC="/opt/occlum/toolchains/gcc/bin/occlum-gcc -I$INC_DIR_MUSL"
        OCCLUMCXX="/opt/occlum/toolchains/gcc/bin/occlum-g++ -I$INC_DIR_MUSL"
    fi
    shift 2
fi
export CC=$OCCLUMCC
export CXX=$OCCLUMCXX
export PATH=$INSTALLDIR/bin:$PATH
export PKG_CONFIG_LIBDIR=$INSTALLDIR/lib:$PKG_CONFIG_LIBDIR
export PKG_CONFIG_PATH=$PKGCONFIGPATH:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=$INSTALLDIR/lib:$INSTALLDIR/lib64:$LD_LIBRARY_PATH

# Build specified component or all by default
BUILD_COMPONENTS="${1:-$ALL_COMPONENTS}"

# Download all components once here together
mkdir -p $DEPSDIR && cd $DEPSDIR || exit 1
# TRYGET $OPENSSLDIR https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_1_1k.tar.gz
TRYGET $CURLDIR https://github.com/curl/curl/archive/curl-7_70_0.tar.gz
#TRYGET $PROTOBUFDIR https://github.com/protocolbuffers/protobuf/releases/download/v21.6/protobuf-all-21.6.tar.gz
#TRYGET $CARESDIR https://c-ares.haxx.se/download/c-ares-1.14.0.tar.gz
#TRYGET $GRPCDIR https://github.com/grpc/grpc/archive/refs/tags/v1.24.3.tar.gz grpc-1.24.3.tar.gz
GITGET_GRPC

for i in $BUILD_COMPONENTS ; do
    if [ "$BUILDFORCE" == "NO" ] ; then
        ${i}_check && LOG_INFO "[READY] build check for $i" && continue
    fi
    LOG_DEBUG "Building $i ..." && ${i}_build && \
    LOG_DEBUG "Build $i successfully" || ERROR_EXIT "Fail to build $i"
done
