### Compile

```
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- sun55iw3p1_t527_defconfig
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- -j$(nproc)
```

### Flash

```
dd if=/dev/zero of=$1 bs=1M count=20
dd if=boot0_sdcard.fex of=$1 bs=8k seek=1 conv=fsync
dd if=boot_package.fex of=$1 bs=8k seek=2050 conv=fsync
```
