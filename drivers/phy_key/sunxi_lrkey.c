/*
 *  * Copyright 2000-2009
 *   * Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 *    *
 *     * SPDX-License-Identifier:	GPL-2.0+
 *     */
#include <common.h>
#include <asm/io.h>
#include <physical_key.h>
#include <sys_config.h>
#include <fdt_support.h>
#include <console.h>

__attribute__((section(".data")))
static uint32_t keyen_flag = 1;

__weak int sunxi_key_clock_open(void)
{
	return 0;
}

__weak int sunxi_key_clock_close(void)
{
	return 0;
}

__weak int axp_probe_key(void)
{
	return 0;
}

int sunxi_lradc_key_init(void)
{
	struct sunxi_lradc *sunxi_key_base = (struct sunxi_lradc *)SUNXI_KEYADC_BASE;
	uint reg_val = 0;
	int nodeoffset;

	sunxi_key_clock_open();

	reg_val = sunxi_key_base->ctrl;
	reg_val &= ~((7<<1) | (0xffU << 24));
#ifdef CONFIG_MACH_SUN55IW3
	reg_val |= (2<<22);
#endif
	reg_val |=  LRADC_HOLD_EN;
	reg_val |=  LRADC_EN;
	sunxi_key_base->ctrl = reg_val;

	/* disable all key irq */
	sunxi_key_base->intc = 0;
	sunxi_key_base->ints = 0x1f1f;

	nodeoffset = fdt_path_offset(working_fdt, FDT_PATH_KEY_DETECT);
	if (nodeoffset > 0) {
		fdt_getprop_u32(working_fdt, nodeoffset, "keyen_flag", &keyen_flag);
	}

	return 0;
}

int sunxi_key_exit(void)
{
	struct sunxi_lradc *sunxi_key_base = (struct sunxi_lradc *)SUNXI_KEYADC_BASE;

	sunxi_key_base->ctrl = 0;
	/* disable all key irq */
	sunxi_key_base->intc = 0;
	sunxi_key_base->ints = 0x1f1f;

	sunxi_key_clock_close();

	return 0;
}

int sunxi_key_read_vol(int channel)
{
	int key_value = -1;
	struct sunxi_lradc *sunxi_key_base = (struct sunxi_lradc *)SUNXI_KEYADC_BASE;

	if (channel == 0)
		key_value = sunxi_key_base->data0 & 0x3f;
	else if (channel == 1)
		key_value = sunxi_key_base->data1 & 0x3f;

	return key_value;
}

int sunxi_key_read(void)
{
	u32 ints;
	int key = -1;
	struct sunxi_lradc *sunxi_key_base = (struct sunxi_lradc *)SUNXI_KEYADC_BASE;

	if (!keyen_flag) {
		return -1;
	}
	ints = sunxi_key_base->ints;
	/* clear the pending data */
	sunxi_key_base->ints |= (ints & 0x1f);
	/* if there is already data pending,
	 read it */
	if (ints & ADC0_KEYDOWN_PENDING) {
		if (ints & ADC0_DATA_PENDING) {
			key = sunxi_key_base->data0 & 0x3f;
			if (!key) {
				key = -1;
			}
		}
	} else if (ints & ADC0_DATA_PENDING) {
		key = sunxi_key_base->data0 & 0x3f;
		if (!key) {
			key = -1;
		}
	}

	if (key > 0) {
		pr_err("key pressed value=0x%x\n", key);
	}


	return key;
}

int do_key_test(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	struct sunxi_lradc *sunxi_key_base = (struct sunxi_lradc *)SUNXI_KEYADC_BASE;
	u32 power_key = 0;
	int nodeoffset;

	nodeoffset = fdt_path_offset(working_fdt, FDT_PATH_KEY_DETECT);
	if (nodeoffset > 0) {
		fdt_getprop_u32(working_fdt, nodeoffset, "keyen_flag", &keyen_flag);
	}
	if (!keyen_flag) {
		puts("warnning: not support,please set keyen_flag=1 in sys_config.fex\n");
		return -1;
	}

	sunxi_lradc_key_init();
	puts(" press a key:\n");
	sunxi_key_base->ints = 0x1f1f;
	while (!ctrlc()) {
		sunxi_key_read();
		power_key = axp_probe_key();
		if (power_key > 0) {
			break;
		}
	}

	return 0;

}

U_BOOT_CMD(
	key_test, 1, 0,	do_key_test,
	"Test the key value\n",
	""
);
