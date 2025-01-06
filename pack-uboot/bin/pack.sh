#!/bin/bash
rm -f u-boot.fex boot_package.fex sys_config.bin
../tools/script sys_config.fex
cp ../../u-boot.bin u-boot.fex
../tools/update_uboot -no_merge u-boot.fex sys_config.bin
../tools/dragonsecboot -pack boot_package.cfg
