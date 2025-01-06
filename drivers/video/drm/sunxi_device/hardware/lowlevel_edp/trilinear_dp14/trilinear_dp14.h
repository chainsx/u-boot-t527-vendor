/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * inno_edp13.h
 *
 * Copyright (c) 2007-2022 Allwinnertech Co., Ltd.
 * Author: huangyongxing <huangyongxing@allwinnertech.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/
#ifndef __TRILINEAR_DP14_LOWLEVEL_H__
#define __TRILINEAR_DP14_LOWLEVEL_H__

#include <linux/types.h>
#include <asm/io.h>

/*TRILINEAR DP 1.4 register*/
#define TR_LINK_BW_SET					(0x000)
#define TR_LANE_COUNT_SET				(0x004)
#define TR_ENHANCED_FRAME_EN			(0x008)
#define TR_TRAINING_PATTERN_SET			(0x00C)
#define TR_LINK_QUAL_PATTERN_SET		(0x010)
#define TR_SCRAMBLING_DISABLE			(0x014)
#define TR_CAPBILITY_CONFIG				(0x01C)
#define TR_HBR2_SCRAMBLER_RESET			(0x020)
#define TR_DISPLAYPORT_VERSION			(0x024)
#define TR_ALPM_POWER_SET				(0x028)
#define TR_LANE_REMAP_CONTROL			(0x02C)
#define TR_80BIT_PATTERN_0_31			(0x030)
#define TR_80BIT_PATTERN_32_63			(0x034)
#define TR_80BIT_PATTERN_64_79			(0x038)
#define TR_TRANSMITTER_OUTPUT_EN		(0x080)
#define TR_SOFT_RESET					(0x090)
#define TR_INPUT_SOURCE_ENABLE			(0x094)
#define TR_FEC_ENABLE					(0x098)
#define TR_FORCE_SCRAMBLER_RESET		(0x0C0)
#define TR_CORE_CAPABILITIES			(0x0F8)
#define TR_CORE_ID						(0x0FC)
#define TR_AUX_COMMAND					(0x100)
#define TR_AUX_WRITE_FIFO				(0x104)
#define TR_AUX_ADDRESS					(0x108)
#define TR_AUX_CLOCK_DIVIDER			(0x10C)
#define TR_AUX_REPLY_TIMEOUT_INTV		(0x110)
#define TR_HPD_INPUT_STATE				(0x128)
#define TR_INTERRUPT_STATE				(0x130)
#define TR_AUX_REPLY_DATA_FIFO			(0x134)
#define TR_AUX_REPLY_CODE				(0x138)
#define TR_AUX_REPLY_COUNT				(0x13C)
#define TR_INTERRUPT_CAUSE				(0x140)
#define TR_INTERRUPT_MASK				(0x144)
#define TR_REPLY_DATA_COUNT				(0x148)
#define TR_AUX_STATUS					(0x14C)
#define TR_AUX_REPLY_CLOCK_WIDTH		(0x150)
#define TR_AUX_WAKE_ACK_DETECTED		(0x154)
#define TR_GP_HOST_TIMER				(0x158)
#define TR_MST_HOST_TIMER				(0x15C)
#define TR_PHY_STATUS					(0x280)

// forbid to read
#define TR_HDCP_ENABLE					(0x400)
#define TR_HDCP_MODE					(0x404)
#define TR_HDCP_KS_31_0					(0x408)
#define TR_HDCP_KS_63_32				(0x40C)
#define TR_HDCP_KM_31_0					(0x410)
#define TR_HDCP_KM_63_32				(0x414)
#define TR_HDCP_AN_31_0					(0x418)
#define TR_HDCP_AN_63_32				(0x41C)
#define TR_HDCP_AUTHEN_IN_PROCESS		(0x424)
#define TR_HDCP_R0_STATUS				(0x428)
#define TR_HDCP_CIPHER_CONTROL			(0x42C)
#define TR_HDCP_BKSV_31_0				(0x430)
#define TR_HDCP_BKSV_63_32				(0x434)
#define TR_HDCP_AKSV_31_0				(0x438)
#define TR_HDCP_AKSV_63_32				(0x43C)
#define TR_HDCP_LC128_31_0				(0x440)
#define TR_HDCP_LC128_63_32				(0x444)
#define TR_HDCP_LC128_65_64				(0x448)
#define TR_HDCP_LC128_127_96			(0x44C)
#define TR_HDCP_REPEATER				(0x450)
#define TR_HDCP_STREAM_CIPGER_EN		(0x454)
#define TR_HDCP_M0_31_0					(0x458)
#define TR_HDCP_M0_63_32				(0x45C)
#define TR_HDCP_AES_INPUT_SELECT		(0x460)
#define TR_HDCP_AES_COUNTER_DIS			(0x464)
#define TR_HDCP_AES_COUNTER_ADV			(0x468)
#define TR_HDCP_ENCRYPT_CTRL_31_0		(0x46C)
#define TR_HDCP_ENCRYPT_CTRL_63_32		(0x470)
#define TR_HDCP_AES_COUNTER_RESET		(0x474)
#define TR_HDCP_RN_31_0					(0x478)
#define TR_HDCP_RN_63_32				(0x47C)
#define TR_HDCP_RNG_CIPGER_AN			(0x480)
#define TR_HDCP_RNG_AN_31_0				(0x484)
#define TR_HDCP_RNG_AN_63_32			(0x488)
#define TR_HDCP_HOST_TIMER				(0x48C)
#define TR_HDCP_ENCRYPTION_STATUS		(0x490)
#define TR_HDCP_CONTENT_TYPE_31_0		(0x498)
#define TR_HDCP_CONTENT_TYPE_63_32		(0x49C)
#define TR_MST_ENABLE					(0x500)
#define TR_MST_PID_TABLE_ID				(0x504)
#define TR_MST_PID_TABLE_ENTRY			(0x508)
#define TR_SSC_SRC_SELECT				(0x50C)
#define TR_MST_ALLOCATION_TRIG			(0x510)
#define TR_MST_PID_TABLE_SEL			(0x514)
#define TR_MST_PAYLOAD_TABLE			(0x518)
#define TR_MST_ACTIVE					(0x520)
#define TR_MST_LINK_FRAME_CNT			(0x524)
#define TR_MSO_CONFIG					(0x528)
#define TR_DSC_MST_SRC_SEL				(0x700)
#define TR_DSC_BYTE_PER_CHUNK			(0x704)
#define TR_DSC_COMPRESSION_EN			(0x708)
// end of forbid

#define TR_VIDEO_STREAM_ENABLE			(0x800)
#define TR_SECOND_STREAM_ENABLE			(0x804)
#define TR_SRC0_SECOND_DATA_WINDOW		(0x808)
#define TR_SRC0_INPUT_STATUS			(0x80C)
#define TR_SRC0_DATA_CONTROL			(0x810)
#define TR_SRC0_COLORMETRY				(0x814)
#define TR_SRC0_MAIN_STREAM_HTOTAL		(0x820)
#define TR_SRC0_MAIN_STREAM_VTOTAL		(0x824)
#define TR_SRC0_MAIN_STREAM_POLAR		(0x828)
#define TR_SRC0_MAIN_STREAM_HSW			(0x82C)
#define TR_SRC0_MAIN_STREAM_VSW			(0x830)
#define TR_SRC0_MAIN_STREAM_HRES		(0x834)
#define TR_SRC0_MAIN_STREAM_VRES		(0x838)
#define TR_SRC0_MAIN_STREAM_HSTART		(0x83C)
#define TR_SRC0_MAIN_STREAM_VSTART		(0x840)
#define TR_SRC0_MAIN_STREAM_MISC0		(0x844)
#define TR_SRC0_MAIN_STREAM_MISC1		(0x848)
#define TR_SRC0_MVID					(0x84C)
#define TR_SRC0_TU_CONFIG				(0x850)
#define TR_SRC0_NVID					(0x854)
#define TR_SRC0_USER_PIXEL_CNT			(0x858)
#define TR_SRC0_USER_DATA_CNT			(0x85C)
#define TR_SRC0_MAIN_STREAM_INTERLACE	(0x860)
#define TR_SRC0_USER_SYNC_POLAR			(0x864)
#define TR_SRC0_USER_CONTROL			(0x868)
#define TR_SRC0_USER_FIFO_STATUS		(0x86C)
#define TR_SRC0_USER_FRAME_STATUS		(0x870)
#define TR_SEC0_AUDIO_ENABLE			(0x900)
#define TR_SEC0_AUDIO_INPUT_SEL			(0x904)
#define TR_SEC0_CHANNEL_CNT				(0x908)
#define TR_SEC0_OWA_CLOCK_CNT			(0x90C)
#define TR_SEC0_INFOFRAME_ENABLE		(0x910)
#define TR_SEC0_INFOFRAME_RATE			(0x914)
#define TR_SEC0_MAUD					(0x918)
#define TR_SEC0_NAUD					(0x91C)
#define TR_SEC0_AUDIO_CLOCK_MODE		(0x920)
#define TR_SEC0_3D_VSC_DATA				(0x924)
#define TR_SEC0_AUDIO_FIFO				(0x928)
#define TR_SEC0_AUDIO_FIFO_LAST			(0x92C)
#define TR_SEC0_AUDIO_FIFO_READY		(0x930)
#define TR_SEC0_INFOFRAME_SEL			(0x934)
#define TR_SEC0_SDP_BUFFER_DATA			(0x938)
#define TR_SEC0_TIMESTAMP_INTV			(0x93C)
#define TR_SEC0_CS_SRC_FORMAT			(0x940)
#define TR_SEC0_CS_CATAGORY_CODE		(0x944)
#define TR_SEC0_CS_LEN_ORIG_FREQ		(0x948)
#define TR_SEC0_CS_FREQ_CLOCK_ACC		(0x94C)
#define TR_SEC0_CS_COPGRIGHT			(0x950)
#define TR_SEC0_AUDIO_CHANNEL_MAP		(0x954)
#define TR_SEC0_AUDIO_FIFO_OVERFLOW		(0x958)
#define TR_SEC0_PACKET_COUNT			(0x95C)
#define TR_SEC0_CS_USER_DATA			(0x960)
#define TR_SEC0_DATA_PACKET_ID			(0x964)
#define TR_SEC0_ADAPTIVE_SYNC_EN		(0x968)
#define TR_SEC0_OWA_STATUS				(0x96C)
#define TR_SEC0_GTC_COUNT_CONFIG		(0x980)
#define TR_SEC0_GTC_CMD_EDGE			(0x984)
#define TR_SEC0_GTC_AUX_FRAME_SYNC		(0x988)
#define TR_SRC0_EDP_CRC_ENABLE			(0x990)
#define TR_SRC0_EDP_CRC_RED				(0x994)
#define TR_SRC0_EDP_CRC_GREEN			(0x998)
#define TR_SRC0_EDP_CRC_BLUE			(0x99C)
#define TR_SRC0_PSR_3D_ENABLE			(0x9A0)
#define TR_SRC0_PSR_CONFIG				(0x9A4)
#define TR_SRC0_PSR_STATE				(0x9A8)
#define TR_SEC_PSR_STATE_INTERNAL		(0x9AC)
#define TR_PSR2_UPDATE_TOP				(0x9B0)
#define TR_PSR2_UPDATE_BOTTOM			(0x9B4)
#define TR_PSR2_UPDATE_LEFT				(0x9B8)
#define TR_PSR2_UPDATE_WIDTH			(0x9BC)
#define TR_DP_LINK_CLK_CFG				(0x2000)
#define TR_DP_VID_CLK_CFG				(0x2004)
#define TR_DP_MISC_RESERVED				(0x2018)

#define HPD_EVENT_MASK					BIT(0)
#define HPD_IRQ_MASK					BIT(1)
#define REPLY_RECEIVE_IRQ_MASK			BIT(2)
#define REPLY_TIMEOUT_IRQ_MASK			BIT(3)
#define GP_TIMER_IRQ_MASK				BIT(4)
#define HDCP_TIMER_IRQ_MASK				BIT(5)

// IRQ STATE
#define HPD_EVENT						BIT(0)
#define HPD_IRQ							BIT(1)
#define REPLY_RECIEVED					BIT(2)
#define REPLY_TIMEOUT					BIT(3)
#define GP_TIMER_EVENT					BIT(4)
#define HDCP_TIMER_EVENT				BIT(5)
#define MST_TIMER_EVENT					BIT(6)

// AUX STATUS
#define AUX_REPLY_RECEIVED				BIT(0)
#define AUX_REPLY_IN_PROGRESS			BIT(1)
#define AUX_REQUEST_IN_PROGRESS			BIT(2)
#define AUX_REPLY_ERROR					BIT(3)
#define AUX_EXPECT_REPLY				BIT(4)

// AUX REPLY CODE
#define AUX_ACK							0x0
#define NATIVE_AUX_NACK					0x1
#define NATIVE_AUX_DEFER				0x2
#define I2C_AUX_NACK					0x4
#define I2C_AUX_DEFER					0x8

#define AUX_EDP_MODE					0x0
#define AUX_DP_MODE						0x1

// AUX CMD
#define TR_DP_CMD_REQUEST_READ                      (0x09 << 8)
#define TR_DP_CMD_REQUEST_WRITE                     (0x08 << 8)
#define TR_DP_CMD_REQUEST_I2C_READ                  (0x01 << 8)
#define TR_DP_CMD_REQUEST_I2C_WRITE                 (0x00)
#define TR_DP_CMD_REQUEST_I2C_WRITE_STATUS          (0x02 << 8)
#define TR_DP_CMD_REQUEST_I2C_READ_MOT              (0x05 << 8)
#define TR_DP_CMD_REQUEST_I2C_WRITE_MOT             (0x04 << 8)
#define TR_DP_CMD_REQUEST_I2C_WRITE_STATUS_MOT      (0x06 << 8)
#define TR_DP_CMD_REQUEST_ADDRESS_ONLY              (0x01 << 12)
#define TR_DP_CMD_REQUEST_PHY_WAKE                  (0x01 << 13)

#define SETMASK(width, shift)   ((width?((-1U) >> (32-width)):0)  << (shift))
#define CLRMASK(width, shift)   (~(SETMASK(width, shift)))
#define GET_BITS(shift, width, reg)     \
	(((reg) & SETMASK(width, shift)) >> (shift))
#define SET_BITS(shift, width, reg, val) \
	(((reg) & CLRMASK(width, shift)) | (val << (shift)))
#define CLR_BITS(shift, width, reg) \
	(((reg) & CLRMASK(width, shift)))

#endif /*End of file*/
