#!/bin/bash
set -e

export ARCH=arm
CPU_ARCH=armv7-a
TRIPLE=arm-linux-androideabi
NDK_API=26
export TOOLCHAIN="$(pwd)/android-toolchain-$CPU_ARCH"
if [ ! -d $TOOLCHAIN ]; then
    $ANDROID_NDK_HOME/build/tools/make_standalone_toolchain.py --force --unified-headers --api=$NDK_API --arch=$ARCH --stl=libc++ --install-dir="$TOOLCHAIN"
fi
export PATH="$TOOLCHAIN/bin/":"$TOOLCHAIN/$TRIPLE/bin/":"$PATH"

cd Libevent
if [ ! -d .libs ]; then
    ./autogen.sh
    ./configure --disable-shared --host=$TRIPLE --disable-openssl
    make clean
    make -j3
fi
cd ..
LIBEVENT_CFLAGS=-ILibevent/include
LIBEVENT="$LIBEVENT_CFLAGS Libevent/.libs/libevent.a Libevent/.libs/libevent_pthreads.a"


cd libsodium
LIBSODIUM_DIR="$(pwd)/libsodium-android-$CPU_ARCH"
test -f configure || ./autogen.sh
test -d $LIBSODIUM_DIR || ./dist-build/android-$CPU_ARCH.sh
cd ..
LIBSODIUM_CFLAGS=-I${LIBSODIUM_DIR}/include
LIBSODIUM="$LIBSODIUM_CFLAGS ${LIBSODIUM_DIR}/lib/libsodium.a"


cd libutp
test -f libutp.a || (make clean && CC=clang CXX=clang++ make -j3 libutp.a)
cd ..
LIBUTP_CFLAGS=-Ilibutp
LIBUTP=libutp/libutp.a

BTFLAGS="-D_UNICODE -DLINUX -DANDROID"
if [ ! -z "$DEBUG" ]; then
    BTFLAGS="$BTFLAGS -D_DEBUG"
fi
cd libbtdht/btutils
if [ ! -f libbtutils.a ]; then
    for f in src/*.cpp; do
        clang++ -MD -g -pipe -Wall -O0 $BTFLAGS -std=c++14 -fPIC -c $f
    done
    ar rs libbtutils.a *.o
fi
cd ..
if [ ! -f libbtdht.a ]; then
    for f in src/*.cpp; do
        clang++ -MD -g -pipe -Wall -O0 $BTFLAGS -std=c++14 -fPIC -I btutils/src -I src -c $f
    done
    ar rs libbtdht.a *.o
fi
cd ..
LIBBTDHT_CFLAGS="-Ilibbtdht/src -Ilibbtdht/btutils/src $BTFLAGS"
LIBBTDHT="libbtdht/libbtdht.a libbtdht/btutils/libbtutils.a"


cd blocksruntime
test -f libBlocksRuntime.a || CC=clang ./buildlib
cd ..
LIBBLOCKSRUNTIME_CFLAGS=-Iblocksruntime/BlocksRuntime
LIBBLOCKSRUNTIME=blocksruntime/libBlocksRuntime.a


FLAGS="-g -Werror -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-parameter -Wno-unused-variable -Wno-error=shadow -Wfatal-errors \
  -fPIC -fblocks -fdata-sections -ffunction-sections \
  -fno-rtti -fno-exceptions -fno-common -fno-inline -fno-optimize-sibling-calls -funwind-tables -fno-omit-frame-pointer -fstack-protector-all \
  -D__FAVOR_BSD -D_BSD_SOURCE"
if [ ! -z "$DEBUG" ]; then
    FLAGS="$FLAGS -O0 -DDEBUG=1"
else
    FLAGS="$FLAGS -O3"
fi

CFLAGS="$FLAGS -std=gnu11"
CPPFLAGS="$FLAGS -std=c++14"

clang++ $CPPFLAGS $LIBBTDHT_CFLAGS $LIBSODIUM_CFLAGS $LIBBLOCKSRUNTIME_CFLAGS -c dht.cpp
for file in android.c bev_splice.c base64.c client.c http.c log.c icmp_handler.c hash_table.c network.c sha1.c timer.c utp_bufferevent.c; do
    clang $CFLAGS $LIBUTP_CFLAGS $LIBEVENT_CFLAGS $LIBBTDHT_CFLAGS $LIBSODIUM_CFLAGS $LIBBLOCKSRUNTIME_CFLAGS -c $file
done
clang++ $FLAGS -shared -o libdcdn.so *.o -static-libstdc++ -lm $LIBUTP $LIBBTDHT $LIBEVENT $LIBSODIUM $LIBBLOCKSRUNTIME -llog
if [ -z "$DEBUG" ]; then
    strip -x libdcdn.so
fi
ls -l libdcdn.so
