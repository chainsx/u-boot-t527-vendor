#
# (C) Copyright 2013-2016
# Allwinner Technology Co., Ltd. <www.allwinnertech.com>
#
# SPDX-License-Identifier:     GPL-2.0+
#



obj-y += sprite_cartoon.o
obj-y += sprite_progressbar/sprite_progressbar.o
obj-y += sprite_draw/sprite_draw.o
obj-$(CONFIG_SUNXI_SPRITE_CARTOON_CHAR) += sprite_char/sprite_char.o
obj-$(CONFIG_SUNXI_SPRITE_CARTOON_CHAR) += sprite_char/sfte/FontEngine.o
obj-$(CONFIG_SUNXI_SPRITE_CARTOON_CHAR) += sprite_char/sfte/sfte.o

subdir-ccflags-$(CONFIG_SUNXI_FINS_FUNC_BOARD_DIR) += -finstrument-functions
