/*
 * Allwinner SoCs hdmi2.0 driver.
 *
 * Copyright (C) 2016 Allwinner.
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include "irq.h"

typedef struct irq_vector {
	irq_sources_t source;
	unsigned int stat_reg;
	unsigned int mute_reg;
} irq_vector_t;

static irq_vector_t irq_vec[] = {
	{AUDIO_PACKETS,	IH_FC_STAT0, IH_MUTE_FC_STAT0},
	{OTHER_PACKETS,	IH_FC_STAT1, IH_MUTE_FC_STAT1},
	{PACKETS_OVERFLOW, IH_FC_STAT2,	IH_MUTE_FC_STAT2},
	{AUDIO_SAMPLER,	IH_AS_STAT0, IH_MUTE_AS_STAT0},
	{PHY, IH_PHY_STAT0, IH_MUTE_PHY_STAT0},
	{I2C_DDC, IH_I2CM_STAT0, IH_MUTE_I2CM_STAT0},
	{CEC, IH_CEC_STAT0, IH_MUTE_CEC_STAT0},
	{VIDEO_PACKETIZER, IH_VP_STAT0,	IH_MUTE_VP_STAT0},
	{I2C_PHY, IH_I2CMPHY_STAT0, IH_MUTE_I2CMPHY_STAT0},
	{AUDIO_DMA, IH_AHBDMAAUD_STAT0, IH_MUTE_AHBDMAAUD_STAT0},
	{0, 0, 0},
};

int irq_read_stat(hdmi_tx_dev_t *dev, irq_sources_t irq_source, u8 *stat)
{
	int i = 0;

	for (i = 0; irq_vec[i].source != 0; i++) {
		if (irq_vec[i].source == irq_source) {
			*stat = dev_read(dev, irq_vec[i].stat_reg);
			HDMI_INFO_MSG("IRQ read state: irq[%d] stat[%d]\n",
							irq_source, *stat);
			return TRUE;
		}
	}
	HDMI_INFO_MSG("IRQ source [%d] is not supported\n", irq_source);
	*stat = 0;
	return FALSE;
}

/*******************************************************************
 * Clear IRQ miscellaneous
 */
int irq_clear_source(hdmi_tx_dev_t *dev, irq_sources_t irq_source)
{
	int i = 0;

	for (i = 0; irq_vec[i].source != 0; i++) {
		if (irq_vec[i].source == irq_source) {
			HDMI_INFO_MSG("IRQ write clear: irq[%d] mask[%d]\n",
							irq_source, 0xff);
			dev_write(dev, irq_vec[i].stat_reg,  0xff);
			return TRUE;
		}
	}
	HDMI_INFO_MSG("IRQ source [%d] is not supported\n", irq_source);
	return FALSE;
}

int irq_clear_bit(hdmi_tx_dev_t *dev, irq_sources_t irq_source, u8 bit_mask)
{
	int i = 0;

	for (i = 0; irq_vec[i].source != 0; i++) {
		if (irq_vec[i].source == irq_source) {
			HDMI_INFO_MSG("IRQ write clear bit: irq[%d] bitmask[%d]\n",
							irq_source, bit_mask);
			dev_write_mask(dev, irq_vec[i].stat_reg, bit_mask, 1);
			return TRUE;
		}
	}

	HDMI_INFO_MSG("IRQ source [%d] is not supported\n", irq_source);
	return FALSE;
}

/*******************************************************************
 * Mute IRQ miscellaneous
 */
int irq_mute_source(hdmi_tx_dev_t *dev, irq_sources_t irq_source)
{
	int i = 0;

	for (i = 0; irq_vec[i].source != 0; i++) {
		if (irq_vec[i].source == irq_source) {
			HDMI_INFO_MSG("IRQ write mute: irq[%d] mask[%d]\n",
							irq_source, 0xff);
			dev_write(dev, irq_vec[i].mute_reg,  0xff);
			return TRUE;
		}
	}
	HDMI_INFO_MSG("IRQ source [%d] is not supported\n", irq_source);
	return FALSE;
}

/*******************************************************************
 * Unmute IRQ miscellaneous
 */
int irq_unmute_source(hdmi_tx_dev_t *dev, irq_sources_t irq_source)
{
	int i = 0;

	for (i = 0; irq_vec[i].source != 0; i++) {
		if (irq_vec[i].source == irq_source) {
			HDMI_INFO_MSG("IRQ write unmute: irq[%d] mask[%d]\n",
							irq_source, 0x0);
			dev_write(dev, irq_vec[i].mute_reg,  0x00);
			return TRUE;
		}
	}
	HDMI_INFO_MSG("IRQ source [%d] is supported\n", irq_source);
	return FALSE;
}


int irq_mask_bit(hdmi_tx_dev_t *dev, irq_sources_t irq_source, u8 bit_mask)
{
	int i = 0;

	for (i = 0; irq_vec[i].source != 0; i++) {
		if (irq_vec[i].source == irq_source) {
			HDMI_INFO_MSG("IRQ mask bit: irq[%d] bit_mask[%d]\n",
							irq_source, bit_mask);
			dev_write_mask(dev, irq_vec[i].mute_reg, bit_mask, 1);
			return TRUE;
		}
	}
	HDMI_INFO_MSG("IRQ source [%d] is not supported\n", irq_source);
	return FALSE;
}

int irq_unmask_bit(hdmi_tx_dev_t *dev, irq_sources_t irq_source, u8 bit_mask)
{
	int i = 0;

	for (i = 0; irq_vec[i].source != 0; i++) {
		if (irq_vec[i].source == irq_source) {
			HDMI_INFO_MSG("IRQ unmask bit: irq[%d] bit_mask[%d]\n",
						irq_source, bit_mask);
			dev_write_mask(dev, irq_vec[i].mute_reg, bit_mask, 0);
			return TRUE;
		}
	}
	HDMI_INFO_MSG("IRQ source [%d] is not supported\n", irq_source);
	return FALSE;
}

/*******************************************************************
 *
 */

void irq_mute(hdmi_tx_dev_t *dev)
{
	LOG_TRACE();
	dev_write(dev, IH_MUTE,  0x3);
}

void irq_unmute(hdmi_tx_dev_t *dev)
{
	LOG_TRACE();
	dev_write(dev, IH_MUTE,  0x0);
}

void irq_clear_all(hdmi_tx_dev_t *dev)
{
	LOG_TRACE();
	irq_clear_source(dev, AUDIO_PACKETS);
	irq_clear_source(dev, OTHER_PACKETS);
	irq_clear_source(dev, PACKETS_OVERFLOW);
	irq_clear_source(dev, AUDIO_SAMPLER);
	irq_clear_source(dev, PHY);
	irq_clear_source(dev, I2C_DDC);
	irq_clear_source(dev, CEC);
	irq_clear_source(dev, VIDEO_PACKETIZER);
	irq_clear_source(dev, I2C_PHY);
	irq_clear_source(dev, AUDIO_DMA);
}

void irq_mask_all(hdmi_tx_dev_t *dev)
{
	LOG_TRACE();
	irq_mute(dev);
	irq_mute_source(dev, AUDIO_PACKETS);
	irq_mute_source(dev, OTHER_PACKETS);
	irq_mute_source(dev, PACKETS_OVERFLOW);
	irq_mute_source(dev, AUDIO_SAMPLER);
	irq_mute_source(dev, PHY);
	irq_mute_source(dev, I2C_DDC);
	irq_mute_source(dev, CEC);
	irq_mute_source(dev, VIDEO_PACKETIZER);
	irq_mute_source(dev, I2C_PHY);
	irq_mute_source(dev, AUDIO_DMA);
}

void irq_scdc_read_request(hdmi_tx_dev_t *dev, int enable)
{
	if (enable)
		irq_unmask_bit(dev, I2C_DDC,
			IH_MUTE_I2CM_STAT0_SCDC_READREQ_MASK);
	else
		irq_mask_bit(dev, I2C_DDC,
			IH_MUTE_I2CM_STAT0_SCDC_READREQ_MASK);
}

void un_mask_i2c_interrupt(hdmi_tx_dev_t *dev)
{
	irq_clear_source(dev, I2C_DDC);

	/* scdc_readreq */
	irq_unmask_bit(dev, I2C_DDC, IH_MUTE_I2CM_STAT0_I2CMASTERERROR_MASK);
	/* I2Cmasterdone */
	irq_unmask_bit(dev, I2C_DDC, IH_MUTE_I2CM_STAT0_I2CMASTERDONE_MASK);
	/* I2Cmastererror */
	irq_unmask_bit(dev, I2C_DDC, IH_MUTE_I2CM_STAT0_SCDC_READREQ_MASK);
}

void irq_hpd_sense_enable(hdmi_tx_dev_t *dev, u8 enable)
{
	LOG_TRACE();

	if (enable) {
		i2cddc_fast_mode(dev, 0);

		/* Enable HDMI TX PHY HPD Detector */
		ctrl_phy_enable_hpd_sense(dev);
	} else {
		ctrl_phy_disable_hpd_sense(dev);
	}
}

u32 read_interrupt_decode(hdmi_tx_dev_t *dev)
{
	return dev_read(dev, IH_DECODE) & 0xFF;
}

int decode_is_fc_stat0(u32 decode)
{
	return (decode & IH_DECODE_IH_FC_STAT0_MASK) ? 1 : 0;
}

int decode_is_fc_stat1(u32 decode)
{
	return (decode & IH_DECODE_IH_FC_STAT1_MASK) ? 1 : 0;
}

int decode_is_fc_stat2_vp(u32 decode)
{
	return (decode & IH_DECODE_IH_FC_STAT2_VP_MASK) ? 1 : 0;
}

int decode_is_as_stat0(u32 decode)
{
	return (decode & IH_DECODE_IH_AS_STAT0_MASK) ? 1 : 0;
}

int decode_is_phy(u32 decode)
{
	return (decode & IH_DECODE_IH_PHY_MASK) ? 1 : 0;
}

int decode_is_phy_lock(u32 decode)
{
	return (decode & IH_PHY_STAT0_TX_PHY_LOCK_MASK) ? 1 : 0;
}

int decode_is_phy_hpd(u32 decode)
{
	return (decode & IH_PHY_STAT0_HPD_MASK) ? 1 : 0;
}

int decode_is_i2c_stat0(u32 decode)
{
	return (decode & IH_DECODE_IH_I2CM_STAT0_MASK) ? 1 : 0;
}

int decode_is_cec_stat0(u32 decode)
{
	return (decode & IH_DECODE_IH_CEC_STAT0_MASK) ? 1 : 0;
}
