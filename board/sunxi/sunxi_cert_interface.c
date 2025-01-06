
/*
 *SPDX-License-Identifier: GPL-2.0+
 */
#include <openssl_ext.h>
#include <asm/arch/ce.h>
#include <sunxi_board.h>

#ifdef CONFIG_CRYPTO
#include <crypto/ecc_dsa.h>
#endif

#ifndef ALG_ECC
#define ALG_ECC         (0x21)
#endif
typedef struct _sunxi_certif_desc {
	int (*pubkey_hash_cal)(u8 *sub_pubkey_hash, u32 sub_pubkey_hash_size,
			       sunxi_certif_info_t *sunxi_certif);
	int (*verify_itself)(sunxi_certif_info_t *sunxi_certif, u8 *buf,
			     u32 len);
	s32 (*asy_sign_check)(struct ecc_verify_params *params,
			      u32 key_byte_size, u8 *hash, u32 hash_byte_len);
} sunxi_certif_desc_t;

sunxi_certif_desc_t toc_certif_desc;
int sunxi_certif_desc_register(u8 *buf);

__weak s32 sunxi_ecc_sign_check(struct ecc_verify_params *params,
				u32 key_byte_size, u8 *hash, u32 hash_byte_len)
{
#ifdef CONFIG_CRYPTO
	u8 *pubkey, *sign;
	int ret;

	pubkey = (u8 *)malloc(params->qx_len * 2);
	memset(pubkey, 0, params->qx_len * 2);
	memcpy(pubkey, params->qx, params->qx_len);
	memcpy(pubkey + params->qx_len, params->qy, params->qy_len);

	sign = (u8 *)malloc(params->r_len * 2);
	memset(sign, 0, params->r_len * 2);
	memcpy(sign, params->r, params->r_len);
	memcpy(sign + params->r_len, params->s, params->s_len);
#ifdef SUNXI_SOFTWARE_ECC_SECP256R1
	/* use software ecc secp256r1 */
	if (uECC_verify(pubkey, hash, hash_byte_len, sign, &curve_secp256r1)) {
		ret = 0;
	} else
#elif defined(SUNXI_SOFTWARE_ECC_SECP384R1)
	/* use software ecc secp384r1 */
	if (uECC_verify(pubkey, hash, hash_byte_len, sign, &curve_secp384r1)) {
		ret = 0;
	} else
#endif  /* SUNXI_SOFTWARE_ECC_SECP256R1 */
	{
		printf("uECC_verify failed\n");
		ret = -1;
	}

	free(sign);
	free(pubkey);
	return ret;
#else
	printf("__weak sunxi_params_check: not support uECC_verify\n");
	return -1;
#endif  /* CONFIG_CRYPTO */
}

int aw_certif_probe_sunxi_certif(sunxi_certif_info_t *sunxi_certif,
				 aw_cert_t *aw_cert)
{
	memcpy((void *)&sunxi_certif->version, aw_cert->head_version,
	       sizeof(aw_cert->head_version));
	sunxi_certif->serial_num = (long)aw_cert->serial_num;
	sunxi_certif->aw_cert_info.public_key_info =
		malloc(AW_CERT_PK_INFO_SIZE);
	if (!sunxi_certif->aw_cert_info.public_key_info) {
		pr_err("malloc failed\n");
		return -1;
	}
	memcpy(sunxi_certif->aw_cert_info.public_key_info,
	       aw_cert->public_key_info, AW_CERT_PK_INFO_SIZE);
	sunxi_certif->aw_cert_info.public_key_size = AW_CERT_PK_INFO_SIZE;
	return 0;
}

#define SELF_STRING "self"
int aw_certif_probe_extern(sunxi_certif_info_t *sunxi_certif,
			   aw_cert_t *p_toc1_cert)
{
	int count = 0;
	char all_zero[8] = { 0 };
	aw_cert_extern_t *aw_cert_extern =
		(aw_cert_extern_t *)p_toc1_cert->reserve;
	sunxi_certif->extension.name[count] = malloc(sizeof(SELF_STRING));
	if (!sunxi_certif->extension.name[count]) {
		return -1;
	}
	memcpy(sunxi_certif->extension.name[count], SELF_STRING,
	       sizeof(SELF_STRING));
	sunxi_certif->extension.value[count] =
		malloc(sizeof(p_toc1_cert->sboot_hash));
	if (!sunxi_certif->extension.value[count]) {
		return -1;
	}
	memcpy(sunxi_certif->extension.value[count], p_toc1_cert->sboot_hash,
	       sizeof(p_toc1_cert->sboot_hash));
	// memcpy(sunxi_certif->extension.name[count], aw_cert_extern->name, sizeof(aw_cert_extern->name));
	sunxi_certif->extension.name_len[count] = sizeof(aw_cert_extern->name);
	// memcpy(sunxi_certif->extension.value[count], aw_cert_extern->value, sizeof(aw_cert_extern->value));
	sunxi_certif->extension.value_len[count] = sizeof(aw_cert_extern->value);
	for (count = 1;
	     count < sizeof(p_toc1_cert->reserve) / sizeof(aw_cert_extern_t);
	     count++) {
		if (memcmp(all_zero, aw_cert_extern->name,
			   sizeof(aw_cert_extern->name))) {
			// printf("dump %c%c%c%c%c%c in  rootcert\n",
			//        *((char *)(aw_cert_extern->name)),
			//        *((char *)(aw_cert_extern->name) + 1),
			//        *((char *)(aw_cert_extern->name) + 2),
			//        *((char *)(aw_cert_extern->name) + 3),
			//        *((char *)(aw_cert_extern->name) + 4),
			//        *((char *)(aw_cert_extern->name) + 5),
			// 	   *((char *)(aw_cert_extern->name) + 6));
			// ndump(aw_cert_extern->value,
			//       sizeof(aw_cert_extern->value));
			sunxi_certif->extension.name[count] =
				malloc(sizeof(aw_cert_extern->name));
			if (!sunxi_certif->extension.name[count]) {
				return -1;
			}
			memcpy(sunxi_certif->extension.name[count],
			       aw_cert_extern->name,
			       sizeof(aw_cert_extern->name));
			sunxi_certif->extension.value[count] =
				malloc(sizeof(aw_cert_extern->value));
			if (!sunxi_certif->extension.value[count]) {
				return -1;
			}
			memcpy(sunxi_certif->extension.value[count],
			       aw_cert_extern->value,
			       sizeof(aw_cert_extern->value));
			// memcpy(sunxi_certif->extension.name[count], aw_cert_extern->name, sizeof(aw_cert_extern->name));
			sunxi_certif->extension.name_len[count] =
				sizeof(aw_cert_extern->name);
			// memcpy(sunxi_certif->extension.value[count], aw_cert_extern->value, sizeof(aw_cert_extern->value));
			sunxi_certif->extension.value_len[count] =
				sizeof(aw_cert_extern->value);
			aw_cert_extern++;
		} else {
			//all zero
			break;
		}
	}
	sunxi_certif->extension.extension_num = count;
	// printf("count = %d\n", count);
	return 0;
}

int aw_certif_probe_signature(aw_cert_t *aw_cert, u8 *sign)
{
	memcpy(sign, aw_cert->sign, aw_cert->sign_size);
	return 0;
}

static void parse_aw_cert_publickey(aw_cert_t *p_toc0_cert,
				    struct ecc_verify_params *params)
{
	aw_cert_ecc_pk_info_t *ecc_pk_info =
		(aw_cert_ecc_pk_info_t *)p_toc0_cert->public_key_info;
	params->p = ecc_pk_info->p;
	params->a = ecc_pk_info->a;
	params->n = ecc_pk_info->n;
	params->gx = ecc_pk_info->gx;
	params->gy = ecc_pk_info->gy;
	params->qx = ecc_pk_info->qx;
	params->qy = ecc_pk_info->qy;
	params->p_len = ecc_pk_info->p_len;
	params->a_len = ecc_pk_info->a_len;
	params->n_len = ecc_pk_info->n_len;
	params->gx_len = ecc_pk_info->gx_len;
	params->gy_len = ecc_pk_info->gy_len;
	params->qx_len = ecc_pk_info->qx_len;
	params->qy_len = ecc_pk_info->qy_len;
	return;
}

static void parse_aw_cert_sign(aw_cert_ecc_sign_t *ecc_sign,
			       struct ecc_verify_params *params)
{
	params->r = ecc_sign->r;
	params->s = ecc_sign->s;
	params->r_len = ecc_sign->r_len;
	params->s_len = ecc_sign->s_len;
	return;
}

static int aw_certif_verify_sign(aw_cert_t *p_toc1_cert,
				 u8 *hash_of_certif, u8 hash_of_certif_len)
{
	struct ecc_verify_params *params = (struct ecc_verify_params *)malloc(
		sizeof(struct ecc_verify_params));
	int ret = 0;
	parse_aw_cert_publickey(p_toc1_cert, params);
	parse_aw_cert_sign((aw_cert_ecc_sign_t *)(p_toc1_cert->sign), params);

	params->sign_type = ALG_ECC;

	// pr_err("dump hash_of_certif(%d)\n", hash_of_certif_len);
	// sunxi_dump(hash_of_certif, hash_of_certif_len);
	if (!toc_certif_desc.asy_sign_check(params, 68, hash_of_certif,
					    hash_of_certif_len)) {
		ret = 0;
	} else {
		pr_err("ecc sign check failed\n");
		ret = -1;
	}
	if (params)
		free(params);
	return ret;
}

int aw_certif_verify_itself(sunxi_certif_info_t *sunxi_certif, u8 *buf, u32 len)
{
	int ret;
	u8 hash_of_certif[64] = { 0 };
	u8 sign_in_certif[256] = { 0 };
	u8 *p_sign_to_calc;
	u8 *align = (u8 *)(((uintptr_t)hash_of_certif + 31) & (~31));
	aw_cert_t *p_toc1_cert = (aw_cert_t *)buf;
	//get cert
	if (aw_certif_probe_sunxi_certif(sunxi_certif,
					 (aw_cert_t *)buf) < 0) {
		return -1;
	}
	if (aw_certif_probe_extern(sunxi_certif, p_toc1_cert) < 0) {
		return -1;
	}
	//get certif sign
	ret = aw_certif_probe_signature((aw_cert_t *)buf,
					sign_in_certif);
	if (ret) {
		printf("fail to probe the sign value\n");
		return -1;
	}
	// printf("dump p_toc1_cert->sign(%d)\n", p_toc1_cert->sign_size);
	// ndump(sign_in_certif, p_toc1_cert->sign_size);
	//get sign data
	p_sign_to_calc = malloc(SUNXI_X509_CERTIFF_MAX_LEN);
	if (!p_sign_to_calc) {
		printf("malloc failed\n");
		ret = -1;
		goto verify_err;
	}
	//get  sign data hash
	memset(hash_of_certif, 0, sizeof(hash_of_certif));
	ret = sunxi_sha_calc(align, 32, (void *)p_toc1_cert,
			     (p_toc1_cert->head_size - RSA_MAX_BYTE));
	if (ret) {
		printf("sunxi_sha_calc: calc sha256 with hardware err\n");
		ret = -1;
		goto verify_err;
	}
	ret = aw_certif_verify_sign(p_toc1_cert, align, 32);
verify_err:
	free(p_sign_to_calc);
	return ret;
}

int sunxi_certif_verify_itself(sunxi_certif_info_t *sunxi_certif, u8 *buf,
			       u32 len)
{
	if (sunxi_certif_desc_register(buf) < 0) {
		printf("sunxi_certif_desc_register failed\n");
		return -1;
	}
	return toc_certif_desc.verify_itself(sunxi_certif, buf, len);
}

int sunxi_ecc_pubkey_hash_cal(u8 *out_buf, u32 hash_size,
			      sunxi_certif_info_t *sunxi_certif)
{
	u8 pkey[ECC_MAX_BYTE * 2 + 32]; //px + py
	u8 *align = (u8 *)(((uintptr_t)pkey + 31) & (~31));
	aw_cert_ecc_pk_info_t *ecc_pk_info =
		(aw_cert_ecc_pk_info_t *)
			sunxi_certif->aw_cert_info.public_key_info;
	memset(pkey, 0x0, sizeof(pkey));
	memcpy(align, ecc_pk_info->qx, ecc_pk_info->qx_len);
	memcpy(align + ecc_pk_info->qx_len, ecc_pk_info->qy,
	       ecc_pk_info->qy_len);
	if (sunxi_sha_calc(out_buf, hash_size, align,
			   ecc_pk_info->qx_len + ecc_pk_info->qy_len)) {
		return -1;
	}
	return 0;
}

int sunxi_rsa_pubkey_hash_cal(u8 *out_buf, u32 hash_size,
			      sunxi_certif_info_t *sunxi_certif);

int sunxi_certif_pubkey_hash_cal(sunxi_certif_info_t *sunxi_certif,
				 u8 *hash_buf)
{
	if (toc_certif_desc.pubkey_hash_cal == NULL) {
		//printf("sunxi_certif_desc_register isn't register, use sunxi certif default\n");
		toc_certif_desc.pubkey_hash_cal = sunxi_rsa_pubkey_hash_cal;
	}
	return toc_certif_desc.pubkey_hash_cal(hash_buf, 32, sunxi_certif);
}

int sunxi_certif_desc_register(u8 *buf)
{
	int ret = 0;

	if (!memcmp(buf, AW_CERT_FORMAT_SIGN, AW_CERT_MAGIC_SIZE)) {
		printf("aw ceritf\n");
		toc_certif_desc.pubkey_hash_cal = sunxi_ecc_pubkey_hash_cal;
		toc_certif_desc.verify_itself = aw_certif_verify_itself;
		toc_certif_desc.asy_sign_check = sunxi_ecc_sign_check;
	} else {
		toc_certif_desc.pubkey_hash_cal = sunxi_rsa_pubkey_hash_cal;
		toc_certif_desc.verify_itself = sunxi_X509_certif_verify_itself;
	}
	return ret;
}
