#!/bin/bash
set -e

export ARCH=arm
CPU_ARCH=armv7-a
TRIPLE=arm-linux-androideabi
NDK_API=23

if [ "$1" == "clean" ]; then
    (cd libutp && make clean || true)
    (cd Libevent && make clean || true)
    (cd libbtdht/btutils && rm *.o libbtutils.a || true)
    (cd libbtdht && rm *.o libbtdht.a || true)
    (cd libsodium && make clean || true)
    (rm -rf libsodium/libsodium-android-$CPU_ARCH)
    (rm -rf ./android-toolchain-armv7-a/)
    (rm -rf ./libsodium/libsodium-android-armv7-a/)
    rm -rf android/.gradle/
    rm -rf android/build/
    rm -rf android/examples/WebViewSample/.gradle/
    rm -rf android/examples/WebViewSample/app/build/
    rm -rf android/examples/WebViewSample/.idea/
    rm -rf android/examples/WebViewSample/build/
    rm -rf android/examples/WebViewSample/local.properties
    rm -rf android/src/main/jniLibs/
    rm libdcdn.so *.o injector client keygen || true
    exit 0
fi

export TOOLCHAIN="$(pwd)/android-toolchain-$CPU_ARCH"
if [ ! -d $TOOLCHAIN ]; then
    $ANDROID_NDK_HOME/build/tools/make_standalone_toolchain.py --force --unified-headers --api=$NDK_API --arch=$ARCH --stl=libc++ --install-dir="$TOOLCHAIN"
fi
export PATH="$TOOLCHAIN/bin/":"$TOOLCHAIN/$TRIPLE/bin/":"$PATH"


#cd openssl
#OPENSSL_DIR="$(pwd)/.android-${NDK_API}"
#if [ ! -d $OPENSSL_DIR ]; then
#    export SYSTEM=android
#    export SYSROOT="$TOOLCHAIN/sysroot"
#    export ANDROID_DEV="$SYSROOT/usr"
#    export MACHINE=armv7
#    export CROSS_COMPILE=$TRIPLE-
#    ./config no-shared -no-ssl2 -no-ssl3 -no-comp -no-hw -no-engine --openssldir="$OPENSSL_DIR"
#    make clean
#    make depend
#    make -j3 all
#    make install_sw
#fi
#cd ..
#OPENSSL_CFLAGS=-I$OPENSSL_DIR/include
#OPENSSL_LDFLAGS="-L$OPENSSL_DIR/lib -lssl -lcrypto"


cd Libevent
if [ ! -d .libs ]; then
    ./autogen.sh
    ./configure --disable-shared --disable-openssl --host=$TRIPLE CFLAGS="-g $OPENSSL_CFLAGS" LDFLAGS="$OPENSSL_LDFLAGS"
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


FLAGS="-g -Werror -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-parameter -Wno-unused-variable -Werror=shadow -Wfatal-errors \
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
`which file` && file libdcdn.so
ls -l libdcdn.so

mkdir -p android/src/main/jniLibs/armeabi
cp libdcdn.so android/src/main/jniLibs/armeabi/
