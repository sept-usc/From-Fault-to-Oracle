#export NDK="$HOME/Library/Android/sdk/ndk/26.1.10909125"

$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android34-clang \
    --sysroot=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/sysroot \
    -fPIE -pie \
    cracktpu_dumpMem_automatic.c -o cracktpu
adb push cracktpu /data/local/tmp/


$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android34-clang \
    --sysroot=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/sysroot \
    -fPIE -pie \
    runner.c -o runner
adb push runner /data/local/tmp/