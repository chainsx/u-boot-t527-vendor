/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright(c) 2020 - 2023 Allwinner Technology Co.,Ltd. All rights reserved. */
/*
 * Allwinner SoCs display driver.
 *
 * Copyright (C) 2017 Allwinner.
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#ifndef _DE_CSC_TYPE_H_
#define _DE_CSC_TYPE_H_

#include <linux/types.h>

union ccsc_ctl_reg {
	u32 dwval;
	struct {
		u32 en:1;
		u32 res0:31;
	} bits;
};

union ccsc_const_reg {
	u32 dwval;
	struct {
		u32 d:10;
		u32 res0:22;
	} bits;
};

union ccsc_coeff_reg {
	u32 dwval;
	struct {
		u32 c:20;
		u32 res0:12;
	} bits;
};

union ccsc_alpha_reg {
	u32 dwval;
	struct {
		u32 alpha:8;
		u32 en:1;
		u32 res0:23;
	} bits;
};

struct csc_reg {
	union ccsc_ctl_reg ctl;

	union ccsc_const_reg d0;
	union ccsc_const_reg d1;
	union ccsc_const_reg d2;

	union ccsc_coeff_reg c0[4];
	union ccsc_coeff_reg c1[4];
	union ccsc_coeff_reg c2[4];

	union ccsc_alpha_reg alpha;
};

union csc2_ctl_reg {
	u32 dwval;
	struct {
		u32 en:1;
		u32 res0:31;
	} bits;
};

union csc2_const_reg {
	u32 dwval;
	struct {
		u32 d:10;
		u32 res0:22;
	} bits;
};

union csc2_coeff_reg {
	u32 dwval;
	struct {
		u32 c:17;
		u32 res0:15;
	} bits;
};

struct csc2_reg {
	union csc2_ctl_reg ctl;

	union csc2_const_reg d0;
	union csc2_const_reg d1;
	union csc2_const_reg d2;

	union csc2_coeff_reg c00;
	union csc2_coeff_reg c01;
	union csc2_coeff_reg c02;
	union csc2_const_reg c03;

	union csc2_coeff_reg c10;
	union csc2_coeff_reg c11;
	union csc2_coeff_reg c12;
	union csc2_const_reg c13;

	union csc2_coeff_reg c20;
	union csc2_coeff_reg c21;
	union csc2_coeff_reg c22;
	union csc2_const_reg c23;
};

#endif /* #ifndef _DE_CSC_TYPE_H_ */
