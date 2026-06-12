/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2020 Craig McQueen for Galois Field operations
 * Copyright (c) 2026 Zixun LI (HiFiPhile)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/* Includes ------------------------------------------------------------------*/
#include "crypt_lib.h"
#include <stdbool.h>
#include <string.h>

static inline void set_uint32_be(uint8_t *dst, uint32_t val) {
    dst[0] = (uint8_t) ((val >> 24) & 0xFF);
    dst[1] = (uint8_t) ((val >> 16) & 0xFF);
    dst[2] = (uint8_t) ((val >> 8) & 0xFF);
    dst[3] = (uint8_t) (val & 0xFF);
}

/* Private typedef -----------------------------------------------------------*/
/* AES state - array holding the intermediate results during decryption. */
typedef uint8_t AES_state_t[4][4];
/* This struct is basically to enable big-integer calculations in the 128-bit Galois field. */
typedef union {
    uint32_t element[4];
    uint8_t bytes[AES_BLOCKLEN];
} AES_gcm_t;
/* Precalculated GF table */
typedef struct
{
    AES_gcm_t keyDataHi[15];
    AES_gcm_t keyDataLo[15];
} AES_gcm_mul_table_t;
/* Union for GCM IV increment */
typedef union {
    uint8_t bytes[AES_BLOCKLEN];
} AES_96b_iv_t;
/* Union for GCM final hash */
typedef union {
    uint8_t bytes[AES_BLOCKLEN];
} AES_gcm_lenhash_t;
/* Private define ------------------------------------------------------------*/
/* The number of columns comprising a state in AES. This is a constant in AES. Value=4 */
#define AES_Nb 4
/* Private macro -------------------------------------------------------------*/
#define MIN(A, B) ((A) <= (B) ? (A) : (B))
/* Private variables ---------------------------------------------------------*/
/* AES Rijndael S-box */
static const uint8_t AES_sbox[256] = {
    // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9,
    0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f,
    0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07,
    0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3,
    0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58,
    0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3,
    0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f,
    0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac,
    0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a,
    0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
    0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
    0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};
/* AES Rijndael Reversed S-box */
static const uint8_t AES_rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39,
    0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2,
    0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76,
    0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc,
    0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d,
    0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c,
    0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f,
    0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62,
    0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd,
    0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60,
    0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6,
    0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};
/* The round constant word array, AES_Rcon[i], contains the values given by
   x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8) */
static const uint8_t AES_Rcon[11] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

/* Precomputed table for Galois 128-bit multiply by 2^8 */
static const uint16_t AES_reduce_table[256] = {
    0x0000u, 0xC201u, 0x8403u, 0x4602u, 0x0807u, 0xCA06u, 0x8C04u, 0x4E05u,
    0x100Eu, 0xD20Fu, 0x940Du, 0x560Cu, 0x1809u, 0xDA08u, 0x9C0Au, 0x5E0Bu,
    0x201Cu, 0xE21Du, 0xA41Fu, 0x661Eu, 0x281Bu, 0xEA1Au, 0xAC18u, 0x6E19u,
    0x3012u, 0xF213u, 0xB411u, 0x7610u, 0x3815u, 0xFA14u, 0xBC16u, 0x7E17u,
    0x4038u, 0x8239u, 0xC43Bu, 0x063Au, 0x483Fu, 0x8A3Eu, 0xCC3Cu, 0x0E3Du,
    0x5036u, 0x9237u, 0xD435u, 0x1634u, 0x5831u, 0x9A30u, 0xDC32u, 0x1E33u,
    0x6024u, 0xA225u, 0xE427u, 0x2626u, 0x6823u, 0xAA22u, 0xEC20u, 0x2E21u,
    0x702Au, 0xB22Bu, 0xF429u, 0x3628u, 0x782Du, 0xBA2Cu, 0xFC2Eu, 0x3E2Fu,
    0x8070u, 0x4271u, 0x0473u, 0xC672u, 0x8877u, 0x4A76u, 0x0C74u, 0xCE75u,
    0x907Eu, 0x527Fu, 0x147Du, 0xD67Cu, 0x9879u, 0x5A78u, 0x1C7Au, 0xDE7Bu,
    0xA06Cu, 0x626Du, 0x246Fu, 0xE66Eu, 0xA86Bu, 0x6A6Au, 0x2C68u, 0xEE69u,
    0xB062u, 0x7263u, 0x3461u, 0xF660u, 0xB865u, 0x7A64u, 0x3C66u, 0xFE67u,
    0xC048u, 0x0249u, 0x444Bu, 0x864Au, 0xC84Fu, 0x0A4Eu, 0x4C4Cu, 0x8E4Du,
    0xD046u, 0x1247u, 0x5445u, 0x9644u, 0xD841u, 0x1A40u, 0x5C42u, 0x9E43u,
    0xE054u, 0x2255u, 0x6457u, 0xA656u, 0xE853u, 0x2A52u, 0x6C50u, 0xAE51u,
    0xF05Au, 0x325Bu, 0x7459u, 0xB658u, 0xF85Du, 0x3A5Cu, 0x7C5Eu, 0xBE5Fu,
    0x00E1u, 0xC2E0u, 0x84E2u, 0x46E3u, 0x08E6u, 0xCAE7u, 0x8CE5u, 0x4EE4u,
    0x10EFu, 0xD2EEu, 0x94ECu, 0x56EDu, 0x18E8u, 0xDAE9u, 0x9CEBu, 0x5EEAu,
    0x20FDu, 0xE2FCu, 0xA4FEu, 0x66FFu, 0x28FAu, 0xEAFBu, 0xACF9u, 0x6EF8u,
    0x30F3u, 0xF2F2u, 0xB4F0u, 0x76F1u, 0x38F4u, 0xFAF5u, 0xBCF7u, 0x7EF6u,
    0x40D9u, 0x82D8u, 0xC4DAu, 0x06DBu, 0x48DEu, 0x8ADFu, 0xCCDDu, 0x0EDCu,
    0x50D7u, 0x92D6u, 0xD4D4u, 0x16D5u, 0x58D0u, 0x9AD1u, 0xDCD3u, 0x1ED2u,
    0x60C5u, 0xA2C4u, 0xE4C6u, 0x26C7u, 0x68C2u, 0xAAC3u, 0xECC1u, 0x2EC0u,
    0x70CBu, 0xB2CAu, 0xF4C8u, 0x36C9u, 0x78CCu, 0xBACDu, 0xFCCFu, 0x3ECEu,
    0x8091u, 0x4290u, 0x0492u, 0xC693u, 0x8896u, 0x4A97u, 0x0C95u, 0xCE94u,
    0x909Fu, 0x529Eu, 0x149Cu, 0xD69Du, 0x9898u, 0x5A99u, 0x1C9Bu, 0xDE9Au,
    0xA08Du, 0x628Cu, 0x248Eu, 0xE68Fu, 0xA88Au, 0x6A8Bu, 0x2C89u, 0xEE88u,
    0xB083u, 0x7282u, 0x3480u, 0xF681u, 0xB884u, 0x7A85u, 0x3C87u, 0xFE86u,
    0xC0A9u, 0x02A8u, 0x44AAu, 0x86ABu, 0xC8AEu, 0x0AAFu, 0x4CADu, 0x8EACu,
    0xD0A7u, 0x12A6u, 0x54A4u, 0x96A5u, 0xD8A0u, 0x1AA1u, 0x5CA3u, 0x9EA2u,
    0xE0B5u, 0x22B4u, 0x64B6u, 0xA6B7u, 0xE8B2u, 0x2AB3u, 0x6CB1u, 0xAEB0u,
    0xF0BBu, 0x32BAu, 0x74B8u, 0xB6B9u, 0xF8BCu, 0x3ABDu, 0x7CBFu, 0xBEBEu};
/* Private function prototypes -----------------------------------------------*/
static void AES_KeyExpansion(uint8_t *RoundKey, const uint8_t *Key, AES_Mode_t Mode);
static void AES_AddRoundKey(uint8_t round, AES_state_t *state, const uint8_t *RoundKey);
static uint8_t AES_xtime(uint8_t x);
static void AES_SubBytes(AES_state_t *state);
static void AES_ShiftRows(AES_state_t *state);
static void AES_MixColumns(AES_state_t *state);
static void AES_InvShiftRows(AES_state_t *state);
static void AES_InvSubBytes(AES_state_t *state);
static void AES_InvMixColumns(AES_state_t *state);
static void AES_BlockXor(const uint8_t *in1, const uint8_t *in2, uint8_t *out);
static void AES_Cipher(AES_state_t *state, const uint8_t *RoundKey, AES_Mode_t Mode);
static void AES_InvCipher(AES_state_t *state, const uint8_t *RoundKey, AES_Mode_t Mode);
static void AES_GCM_TableInit(AES_gcm_mul_table_t *Table, const uint8_t Key[AES_BLOCKLEN]);
static void AES_GCM_Mul(uint8_t Block[AES_BLOCKLEN], const AES_gcm_mul_table_t *Table);
static void AES_GCM_ByteToStruct(AES_gcm_t *Dst, const uint8_t Src[AES_BLOCKLEN]);
static void AES_GCM_StructToByte(uint8_t Dst[AES_BLOCKLEN], const AES_gcm_t *Src);
static void AES_GCM_GFMul2(AES_gcm_t *p);
static void AES_GCM_GFMul256(AES_gcm_t *p);
/* Private functions ---------------------------------------------------------*/

/**
 * @fn	void AES_Init_Ctx(AES_Ctx_t* Ctx, const uint8_t* Key, AES_Mode_t Mode)
 *
 * @brief	AES initialize context.
 *
 * @param [in,out]	Ctx 	AES context.
 * @param 		  	Key 	AES key.
 * @param 		  	Mode	The mode.
 */
void AES_Init_Ctx(AES_Ctx_t *Ctx, const uint8_t *Key, AES_Mode_t Mode) {
    AES_KeyExpansion(Ctx->RoundKey, Key, Mode);
    Ctx->Mode = Mode;
}

/**
 * @fn	void AES_Init_Ctx_Iv(AES_Ctx_t* Ctx, const uint8_t* Key, const uint8_t* Iv, AES_Mode_t Mode)
 *
 * @brief	AES initialize context and Iv.
 *
 * @param [in,out]	Ctx 	AES context.
 * @param 		  	Key 	AES key.
 * @param 		  	Iv  	Initial vector.
 * @param 		  	Mode	The mode.
 */
void AES_Init_Ctx_Iv(AES_Ctx_t *Ctx, const uint8_t *Key, const uint8_t *Iv, AES_Mode_t Mode) {
    AES_KeyExpansion(Ctx->RoundKey, Key, Mode);
    Ctx->Mode = Mode;
    memcpy(Ctx->Iv, Iv, AES_BLOCKLEN);
}

/**
 * @fn	void AES_Ctx_Set_Iv(AES_Ctx_t* Ctx, const uint8_t* Iv)
 *
 * @brief	AES set Iv.
 *
 * @param [in,out]	Ctx	AES context.
 * @param 		  	Iv 	Initial vector.
 */
void AES_Ctx_Set_Iv(AES_Ctx_t *Ctx, const uint8_t *Iv) {
    memcpy(Ctx->Iv, Iv, AES_BLOCKLEN);
}

/**
 * @fn	void AES_Ctx_Set_Iv(AES_Ctx_t* Ctx, const uint8_t* Iv)
 *
 * @brief	AES-CTR set Iv, with 96b nonce / 32b counter.
 *
 * @param [in,out]	Ctx	AES context.
 * @param 		  	Iv 	Initial vector.
 */
void AES_CTR_Ctx_Set_Iv(AES_Ctx_t *Ctx, const uint8_t *Iv, uint32_t Ctr) {
    memcpy(Ctx->Iv, Iv, AES_CTR_IVLEN);
    set_uint32_be(&Ctx->Iv[12], Ctr);
}

/**
 * @fn	void AES_CMAC_Init(AES_CMAC_Ctx_t* Ctx, const uint8_t* Key, AES_Mode_t Mode)
 *
 * @brief	AES-CMAC initialize context.
 *
 * @param [in,out]	Ctx 	AES context.
 * @param 		  	Key 	AES key.
 */
void AES_CMAC_Init(AES_CMAC_Ctx_t *Ctx, const uint8_t *Key, AES_Mode_t Mode) {
    uint8_t L[AES_KEYLEN_128];

    memset(L, 0, AES_KEYLEN_128);

    Ctx->Mode = Mode;
    AES_KeyExpansion(Ctx->RoundKey, Key, Mode);
    AES_Cipher((AES_state_t *) L, Ctx->RoundKey, Mode);

    uint8_t ovf = 0;
    for (int i = AES_KEYLEN_128 - 1; i >= 0; i--) {
        Ctx->K1[i] = L[i] << 1;
        Ctx->K1[i] |= ovf;
        ovf = (L[i] & 0x80) ? 1 : 0;
    }
    if (L[0] & 0x80) {
        Ctx->K1[AES_KEYLEN_128 - 1] ^= 0x87;
    }

    ovf = 0;
    for (int i = AES_KEYLEN_128 - 1; i >= 0; i--) {
        Ctx->K2[i] = Ctx->K1[i] << 1;
        Ctx->K2[i] |= ovf;
        ovf = (Ctx->K1[i] & 0x80) ? 1 : 0;
    }
    if (Ctx->K1[0] & 0x80) {
        Ctx->K2[AES_KEYLEN_128 - 1] ^= 0x87;
    }
}

/**
 * @fn	void AES_ECB_Encrypt(AES_Ctx_t* Ctx, uint8_t* Buf, uint32_t Length)
 *
 * @brief	AES ECB Encrypt.
 *
 * @param [in,out]	Ctx   	AES context.
 * @param [in,out]	Buf   	The buffer.
 * @param 		  	Length	The length.
 */
void AES_ECB_Encrypt(AES_Ctx_t *Ctx, uint8_t *Buf, uint32_t Length) {
    for (uint32_t i = 0; i < Length; i += AES_BLOCKLEN) {
        AES_Cipher((AES_state_t *) Buf, Ctx->RoundKey, Ctx->Mode);
        Buf += AES_BLOCKLEN;
    }
}

/**
 * @fn	void AES_ECB_Decrypt(AES_Ctx_t* Ctx, uint8_t* Buf, uint32_t Length)
 *
 * @brief	AES ECB Decrypt.
 *
 * @param [in,out]	Ctx   	AES context.
 * @param [in,out]	Buf   	The buffer.
 * @param 		  	Length	The length.
 */
void AES_ECB_Decrypt(AES_Ctx_t *Ctx, uint8_t *Buf, uint32_t Length) {
    for (uint32_t i = 0; i < Length; i += AES_BLOCKLEN) {
        AES_InvCipher((AES_state_t *) Buf, Ctx->RoundKey, Ctx->Mode);
        Buf += AES_BLOCKLEN;
    }
}

/**
 * @fn	void AES_CBC_Encrypt(AES_Ctx_t* Ctx, uint8_t* Buf, uint32_t Length)
 *
 * @brief	AES CBC Encrypt.
 *
 * @param [in,out]	Ctx   	AES context.
 * @param [in,out]	Buf   	The buffer.
 * @param 		  	Length	The length.
 */
void AES_CBC_Encrypt(AES_Ctx_t *Ctx, uint8_t *Buf, uint32_t Length) {
    uint8_t *Iv = Ctx->Iv;
    for (uint32_t i = 0; i < Length; i += AES_BLOCKLEN) {
        AES_BlockXor(Buf, Iv, Buf);
        AES_Cipher((AES_state_t *) Buf, Ctx->RoundKey, Ctx->Mode);
        Iv = Buf;
        Buf += AES_BLOCKLEN;
    }
    /* store Iv in Ctx for next call */
    memcpy(Ctx->Iv, Iv, AES_BLOCKLEN);
}

/**
 * @fn	void AES_CBC_Decrypt(AES_Ctx_t* Ctx, uint8_t* Buf, uint32_t Length)
 *
 * @brief	AES CBC Decrypt.
 *
 * @param [in,out]	Ctx   	AES context.
 * @param [in,out]	Buf   	The buffer.
 * @param 		  	Length	The length.
 */
void AES_CBC_Decrypt(AES_Ctx_t *Ctx, uint8_t *Buf, uint32_t Length) {
    uint8_t storeNextIv[AES_BLOCKLEN];
    for (uint32_t i = 0; i < Length; i += AES_BLOCKLEN) {
        memcpy(storeNextIv, Buf, AES_BLOCKLEN);
        AES_InvCipher((AES_state_t *) Buf, Ctx->RoundKey, Ctx->Mode);
        AES_BlockXor(Buf, Ctx->Iv, Buf);
        memcpy(Ctx->Iv, storeNextIv, AES_BLOCKLEN);
        Buf += AES_BLOCKLEN;
    }
}

/**
 * @fn	void AES_CTR_Crypt(AES_Ctx_t* Ctx, uint8_t* Buf, uint32_t Length)
 *
 * @brief	AES CTR Encrypt / Decrypt.
 *
 * @param [in,out]	Ctx   	AES context.
 * @param [in,out]	Buf   	Data buffer.
 * @param 		  	Length	Data length.
 */
void AES_CTR_Crypt(AES_Ctx_t *Ctx, uint8_t *Buf, uint32_t Length) {
    uint8_t buffer[AES_BLOCKLEN];
    /* Reconstruct big-endian 32-bit counter from IV bytes 12..15 */
    uint32_t ctr = ((uint32_t) Ctx->Iv[12] << 24) | ((uint32_t) Ctx->Iv[13] << 16) |
                   ((uint32_t) Ctx->Iv[14] << 8) | (uint32_t) Ctx->Iv[15];

    /* Process full 16-byte blocks */
    while (Length >= AES_BLOCKLEN) {
        memcpy(buffer, Ctx->Iv, AES_BLOCKLEN);
        AES_Cipher((AES_state_t *) buffer, Ctx->RoundKey, Ctx->Mode);
        AES_BlockXor(Buf, buffer, Buf);
        ctr++;
        set_uint32_be(&Ctx->Iv[12], ctr);
        Buf += AES_BLOCKLEN;
        Length -= AES_BLOCKLEN;
    }

    /* Handle remaining partial block */
    if (Length > 0) {
        memcpy(buffer, Ctx->Iv, AES_BLOCKLEN);
        AES_Cipher((AES_state_t *) buffer, Ctx->RoundKey, Ctx->Mode);
        for (uint32_t i = 0; i < Length; i++) {
            Buf[i] ^= buffer[i];
        }
        ctr++;
        set_uint32_be(&Ctx->Iv[12], ctr);
    }
}

/**
 * @fn	void AES_CMAC(AES_CMAC_Ctx_t* Ctx, const uint8_t* Data, uint32_t DataLen, uint8_t* Mac, uint_fast8_t
 * MacLen)
 *
 * @brief	AES-CMAC Calculation.
 *
 * @param [in,out]	Ctx   	AES context.
 * @param       	Data   	Input buffer.
 * @param 		  	DataLen	Data length.
 * @param       	Mac   	Mac buffer.
 * @param 		  	MacLen	Mac length.
 */
void AES_CMAC(AES_CMAC_Ctx_t *Ctx, const uint8_t *Data, uint32_t DataLen, uint8_t *Mac, uint_fast8_t MacLen) {
    uint8_t X[AES_BLOCKLEN], M_last[AES_BLOCKLEN];
    uint32_t n, i;
    bool flag;
    n = (DataLen + AES_BLOCKLEN - 1) / AES_BLOCKLEN; /* n is number of rounds */

    if (n == 0) {
        n = 1;
        flag = false;
    } else {
        if ((DataLen % AES_BLOCKLEN) == 0) { /* last block is a complete block */
            flag = true;
        } else { /* last block is not complete block */
            flag = false;
        }
    }

    if (flag) { /* last block is complete block */
        AES_BlockXor(&Data[AES_BLOCKLEN * (n - 1)], Ctx->K1, M_last);
    } else {
        uint32_t last = DataLen % AES_BLOCKLEN;
        for (i = 0; i < last; i++) {
            M_last[i] = Data[AES_BLOCKLEN * (n - 1) + i];
        }
        M_last[last] = 0x80;
        for (i = last + 1; i < AES_BLOCKLEN; i++) {
            M_last[i] = 0;
        }
        AES_BlockXor(M_last, Ctx->K2, M_last);
    }

    memset(X, 0, AES_BLOCKLEN);
    for (i = 0; i < n - 1; i++) {
        AES_BlockXor(X, &Data[AES_BLOCKLEN * i], X);             /* Y := Mi (+) X  */
        AES_Cipher((AES_state_t *) X, Ctx->RoundKey, Ctx->Mode); /* X := AES-128(KEY, Y); */
    }

    AES_BlockXor(X, M_last, X);
    AES_Cipher((AES_state_t *) X, Ctx->RoundKey, Ctx->Mode);

    if (MacLen > AES_BLOCKLEN)
        MacLen = AES_BLOCKLEN;

    memcpy(Mac, X, MacLen);
}

/**
 * @fn	static void AES_KeyExpansion(uint8_t* RoundKey, const uint8_t* Key, AES_Mode_t Mode)
 *
 * @brief	AES_Nb(Nr+1) round keys expansion
 *
 * @param [in,out]	RoundKey	If non-null, the round key.
 * @param 		  	Key			The key.
 * @param 		  	Mode		The mode.
 */
static void AES_KeyExpansion(uint8_t *RoundKey, const uint8_t *Key, AES_Mode_t Mode) {
    uint_fast8_t Nk, Nr;
    if (Mode == AES_Mode_128) {
        Nk = 4;
        Nr = 10;
    } else if (Mode == AES_Mode_192) {
        Nk = 6;
        Nr = 12;
    } else {
        Nk = 8;
        Nr = 14;
    }

    uint_fast8_t i, j, k;
    uint8_t tempa[4];// Used for the column/row operations

    // The first round key is the key itself.
    for (i = 0; i < Nk; ++i) {
        RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
        RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
        RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
        RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
    }

    // All other round keys are found from the previous round keys.
    for (i = Nk; i < AES_Nb * (Nr + 1); ++i) {
        {
            k = (i - 1) * 4;
            tempa[0] = RoundKey[k + 0];
            tempa[1] = RoundKey[k + 1];
            tempa[2] = RoundKey[k + 2];
            tempa[3] = RoundKey[k + 3];
        }

        if (i % Nk == 0) {
            // This function shifts the 4 bytes in a word to the left once.
            // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

            // Function RotWord()
            {
                const uint8_t u8tmp = tempa[0];
                tempa[0] = tempa[1];
                tempa[1] = tempa[2];
                tempa[2] = tempa[3];
                tempa[3] = u8tmp;
            }

            // SubWord() is a function that takes a four-byte input word and
            // applies the S-box to each of the four bytes to produce an output word.

            // Function Subword()
            {
                tempa[0] = AES_sbox[tempa[0]];
                tempa[1] = AES_sbox[tempa[1]];
                tempa[2] = AES_sbox[tempa[2]];
                tempa[3] = AES_sbox[tempa[3]];
            }

            tempa[0] = tempa[0] ^ AES_Rcon[i / Nk];
        }
        if (Mode == AES_Mode_256) {
            if (i % Nk == 4) {
                // Function Subword()
                {
                    tempa[0] = AES_sbox[tempa[0]];
                    tempa[1] = AES_sbox[tempa[1]];
                    tempa[2] = AES_sbox[tempa[2]];
                    tempa[3] = AES_sbox[tempa[3]];
                }
            }
        }
        j = i * 4;
        k = (i - Nk) * 4;
        RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
        RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
        RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
        RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
    }
}

/**
 * @fn	static void AES_AddRoundKey(uint8_t round, AES_state_t* state, uint8_t* RoundKey)
 *
 * @brief	Adds the round key to state. The round key is added to the state by an XOR function.
 *
 * @param 		  	round   	The round.
 * @param [in,out]	state   	If non-null, the state.
 * @param [in,out]	RoundKey	If non-null, the round key.
 */
static void AES_AddRoundKey(uint8_t round, AES_state_t *state, const uint8_t *RoundKey) {
    /* Direct 32-bit XOR per column — avoids memcpy overhead on ARM */
    const uint32_t *rk = (const uint32_t *)&RoundKey[round * AES_Nb * 4];
    uint32_t *st = (uint32_t *)(*state);
    st[0] ^= rk[0];
    st[1] ^= rk[1];
    st[2] ^= rk[2];
    st[3] ^= rk[3];
}

static uint8_t AES_xtime(uint8_t x) {
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

/**
 * @fn	static void AES_SubBytes(AES_state_t* state)
 *
 * @brief	Substitutes the values in the state matrix with values in an S-box.
 *
 * @param [in,out]	state	If non-null, the state.
 */
static void AES_SubBytes(AES_state_t *state) {
    uint8_t i, j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            (*state)[j][i] = AES_sbox[(*state)[j][i]];
        }
    }
}

/**
 * @fn	static void AES_ShiftRows(AES_state_t* state)
 *
 * @brief	Shifts the rows in the state to the left. Each row is
 * 			shifted with different offset. Offset = Row number. So the first row is not shifted.
 *
 * @param [in,out]	state	If non-null, the state.
 */
static void AES_ShiftRows(AES_state_t *state) {
    uint8_t temp;

    // Rotate first row 1 columns to left
    temp = (*state)[0][1];
    (*state)[0][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[3][1];
    (*state)[3][1] = temp;

    // Rotate second row 2 columns to left
    temp = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    // Rotate third row 3 columns to left
    temp = (*state)[0][3];
    (*state)[0][3] = (*state)[3][3];
    (*state)[3][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[1][3];
    (*state)[1][3] = temp;
}

/**
 * @fn	static void AES_MixColumns(AES_state_t* state)
 *
 * @brief	Mixes the columns of the state matrix
 *
 * @param [in,out]	state	If non-null, the state.
 */
static void AES_MixColumns(AES_state_t *state) {
    uint8_t i;
    uint8_t Tmp, Tm, t;
    for (i = 0; i < 4; ++i) {
        t = (*state)[i][0];
        Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
        Tm = (*state)[i][0] ^ (*state)[i][1];
        Tm = AES_xtime(Tm);
        (*state)[i][0] ^= Tm ^ Tmp;
        Tm = (*state)[i][1] ^ (*state)[i][2];
        Tm = AES_xtime(Tm);
        (*state)[i][1] ^= Tm ^ Tmp;
        Tm = (*state)[i][2] ^ (*state)[i][3];
        Tm = AES_xtime(Tm);
        (*state)[i][2] ^= Tm ^ Tmp;
        Tm = (*state)[i][3] ^ t;
        Tm = AES_xtime(Tm);
        (*state)[i][3] ^= Tm ^ Tmp;
    }
}

/**
 * @fn	static void AES_InvShiftRows(AES_state_t* state)
 *
 * @brief	AES inverse shift rows
 *
 * @param [in,out]	state	If non-null, the state.
 */
static void AES_InvShiftRows(AES_state_t *state) {
    uint8_t temp;

    // Rotate first row 1 columns to right
    temp = (*state)[3][1];
    (*state)[3][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[0][1];
    (*state)[0][1] = temp;

    // Rotate second row 2 columns to right
    temp = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    // Rotate third row 3 columns to right
    temp = (*state)[0][3];
    (*state)[0][3] = (*state)[1][3];
    (*state)[1][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[3][3];
    (*state)[3][3] = temp;
}

/**
 * @fn	static void AES_InvSubBytes(AES_state_t* state)
 *
 * @brief	Substitutes the values in the state matrix with values in an S-box.
 *
 * @param [in,out]	state	If non-null, the state.
 */
static void AES_InvSubBytes(AES_state_t *state) {
    uint8_t i, j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            (*state)[j][i] = AES_rsbox[(*state)[j][i]];
        }
    }
}

/**
 * @fn	static void AES_InvMixColumns(AES_state_t* state)
 *
 * @brief	AES_MixColumns function mixes the columns of the state matrix.
 *
 * @param [in,out]	state	If non-null, the state.
 */
static void AES_InvMixColumns(AES_state_t *state) {
    int i;
    uint8_t a, b, c, d, T, X;
    for (i = 0; i < 4; ++i) {
        a = (*state)[i][0];
        b = (*state)[i][1];
        c = (*state)[i][2];
        d = (*state)[i][3];

        // Let "*" denotes polynomial multiplication modulo x^4+1 over GF(2^8)
        // Let "+" denotes polynimial addition over GF(2^8) (XOR)
        // xtime(X) is X*2
        // A' = (A*8 + A*4 + A*2) + (B*8 + B*2 + B) + (C*8 + C*4 + C) + (D*8 + D)
        // B' = (A*8 + A) + (B*8 + B*4 + B*2) + (C*8 + C*2 + C) + (D*8 + D*4 + D)
        // C' = (A*8 + A*4 + A) + (B*8 + B) + (C*8 + C*4 + C*2) + (D*8 + D*2 + D)
        // D' = (A*8 + A*2 + A) + (B*8 + B*4 + B) + (C*8 + C) + (D*8 + D*4 + D*2)
        // Let T = (A + B + C + D)*8 + (A + B + C + D)
        // Then
        // A' = T + (A + C)*4 + (A + B)*2 + A
        // B' = T + (B + D)*4 + (B + C)*2 + B
        // C' = T + (C + A)*4 + (C + D)*2 + C
        // D' = T + (D + B)*4 + (D + A)*2 + D
        // Let X = (A + C)*4 or (B + D)*4
        T = a ^ b ^ c ^ d;
        T ^= AES_xtime(AES_xtime(AES_xtime(T)));
        X = AES_xtime(AES_xtime(a ^ c));
        (*state)[i][0] = T ^ X ^ AES_xtime(a ^ b) ^ a;
        (*state)[i][2] = T ^ X ^ AES_xtime(c ^ d) ^ c;
        X = AES_xtime(AES_xtime(b ^ d));
        (*state)[i][1] = T ^ X ^ AES_xtime(b ^ c) ^ b;
        (*state)[i][3] = T ^ X ^ AES_xtime(d ^ a) ^ d;
    }
}

/**
 * @fn	static void AES_BlockXor(const uint8_t* in1, const uint8_t* in2, uint8_t* out)
 *
 * @brief	Block Exclusive-or
 *
 * @param [in]	in1	1st input.
 * @param [in]	in2 2nd input.
 * @param [out]	out output.
 *
 */
static void AES_BlockXor(const uint8_t *in1, const uint8_t *in2, uint8_t *out) {
    /* Direct 32-bit word XOR — all AES blocks are 4-byte aligned */
    ((uint32_t *)out)[0] = ((const uint32_t *)in1)[0] ^ ((const uint32_t *)in2)[0];
    ((uint32_t *)out)[1] = ((const uint32_t *)in1)[1] ^ ((const uint32_t *)in2)[1];
    ((uint32_t *)out)[2] = ((const uint32_t *)in1)[2] ^ ((const uint32_t *)in2)[2];
    ((uint32_t *)out)[3] = ((const uint32_t *)in1)[3] ^ ((const uint32_t *)in2)[3];
}

/**
 * @fn	static void AES_Cipher(AES_state_t* state, uint8_t* RoundKey, AES_Mode_t Mode)
 *
 * @brief	AES_Cipher is the main function that encrypts the PlainText.
 *
 * @param [in,out]	state   	If non-null, the state.
 * @param [in,out]	RoundKey	If non-null, the round key.
 * @param 		  	Mode		The mode.
 */
static void AES_Cipher(AES_state_t *state, const uint8_t *RoundKey, AES_Mode_t Mode) {
    uint_fast8_t Nr;
    if (Mode == AES_Mode_128) {
        Nr = 10;
    } else if (Mode == AES_Mode_192) {
        Nr = 12;
    } else {
        Nr = 14;
    }
    uint8_t round = 0;

    // Add the First round key to the state before starting the rounds.
    AES_AddRoundKey(0, state, RoundKey);

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr-1 rounds are executed in the loop below.
    for (round = 1; round < Nr; ++round) {
        AES_SubBytes(state);
        AES_ShiftRows(state);
        AES_MixColumns(state);
        AES_AddRoundKey(round, state, RoundKey);
    }

    // The last round is given below.
    // The AES_MixColumns function is not here in the last round.
    AES_SubBytes(state);
    AES_ShiftRows(state);
    AES_AddRoundKey(Nr, state, RoundKey);
}

/**
 * @fn	static void AES_InvCipher(AES_state_t* state, uint8_t* RoundKey, AES_Mode_t Mode)
 *
 * @brief	AES inverse cipher.
 *
 * @param [in,out]	state   	If non-null, the state.
 * @param [in,out]	RoundKey	If non-null, the round key.
 * @param 		  	Mode		The mode.
 */
static void AES_InvCipher(AES_state_t *state, const uint8_t *RoundKey, AES_Mode_t Mode) {
    uint_fast8_t Nr;
    if (Mode == AES_Mode_128) {
        Nr = 10;
    } else if (Mode == AES_Mode_192) {
        Nr = 12;
    } else {
        Nr = 14;
    }
    uint8_t round = 0;

    // Add the First round key to the state before starting the rounds.
    AES_AddRoundKey(Nr, state, RoundKey);

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr-1 rounds are executed in the loop below.
    for (round = (Nr - 1); round > 0; --round) {
        AES_InvShiftRows(state);
        AES_InvSubBytes(state);
        AES_AddRoundKey(round, state, RoundKey);
        AES_InvMixColumns(state);
    }

    // The last round is given below.
    // The AES_MixColumns function is not here in the last round.
    AES_InvShiftRows(state);
    AES_InvSubBytes(state);
    AES_AddRoundKey(0, state, RoundKey);
}

/**
 * @fn	void AES_GCM_Init_Ctx(AES_Ctx_t* Ctx, const uint8_t* Key, AES_Mode_t Mode)
 *
 * @brief	AES-GCM initialize context.
 *
 * @param [in,out]	Ctx 	AES context.
 * @param 		  	Key 	AES key.
 * @param 		  	Mode	The mode.
 */
void AES_GCM_Init_Ctx(AES_GCM_Ctx_t *Ctx, const uint8_t *Key, AES_Mode_t Mode) {
    uint8_t ghash_work[AES_BLOCKLEN];

    AES_KeyExpansion(Ctx->RoundKey, Key, Mode);
    Ctx->Mode = Mode;

    memset(ghash_work, 0, AES_BLOCKLEN);
    AES_Cipher((AES_state_t *) ghash_work, Ctx->RoundKey, Mode);

    AES_GCM_TableInit((AES_gcm_mul_table_t *) (uintptr_t) Ctx->Table, ghash_work);
}

/**
 * @fn	void AES_GCM_Ctx_Set_Iv(AES_GCM_Ctx_t* Ctx, const uint8_t* Iv)
 *
 * @brief	AES-GCM set Iv.
 *
 * @param [in,out]	Ctx	AES context.
 * @param 		  	Iv  Initial vector.
 */
void AES_GCM_Ctx_Set_Iv(AES_GCM_Ctx_t *Ctx, const uint8_t *Iv) {
    memcpy(Ctx->Iv, Iv, AES_GCM_IVLEN);
}

/**
 * @fn	void AES_GCM_Init_Ctx_Iv(AES_GCM_Ctx_t* Ctx, const uint8_t* Key, const uint8_t* Iv, AES_Mode_t
 * Mode)
 *
 * @brief	AES-GCM initialize context and Iv.
 *
 * @param [in,out]	Ctx 	AES context.
 * @param 		  	Key 	AES key.
 * @param 		  	Iv  	Initial vector.
 * @param 		  	Mode	The mode.
 */
void AES_GCM_Init_Ctx_Iv(AES_GCM_Ctx_t *Ctx, const uint8_t *Key, const uint8_t *Iv, AES_Mode_t Mode) {
    AES_GCM_Init_Ctx(Ctx, Key, Mode);

    memcpy(Ctx->Iv, Iv, AES_GCM_IVLEN);
}

/**
 * @fn	void AES_GCM_Encrypt(AES_GCM_Ctx_t* Ctx, uint8_t* Data, uint32_t DataLen, const uint8_t* AAD, uint32_t AADLen, uint8_t* Tag, uint8_t TagLen)
 *
 * @brief	AES-GCM Encrypt.
 *
 * @param [in,out]	Ctx   	AES context.
 * @param [in,out]	Data   	Data to be encrypted.
 * @param 		  	DataLen	Data length.
 * @param [in]	    AAD   	Additional authenticated data.
 * @param 		  	AADLen	AAD length.
 * @param [out]	    Tag   	Authentication tag.
 * @param 		  	TagLen	Tag length.
 */
void AES_GCM_Encrypt(AES_GCM_Ctx_t *Ctx, uint8_t *Data, uint32_t DataLen, const uint8_t *AAD, uint32_t AADLen, uint8_t *Tag, uint8_t TagLen) {
    AES_96b_iv_t iv_block;
    AES_gcm_lenhash_t ghash_lengths;
    uint8_t *p_data;
    uint32_t data_len;
    uint8_t data_block[AES_BLOCKLEN];
    uint8_t aes_work[AES_BLOCKLEN];
    uint8_t ghash_work[AES_BLOCKLEN];
    uint8_t ej0[AES_BLOCKLEN]; /* Pre-computed E(J₀) = AES(K, IV||0^31||1) */

    /* Prepare working IV. */
    memcpy(iv_block.bytes, Ctx->Iv, AES_GCM_IVLEN);
    set_uint32_be(iv_block.bytes + 12, 1);

    /* Pre-compute E(J₀) for final tag XOR — avoids redundant AES_Cipher at end. */
    memcpy(ej0, iv_block.bytes, AES_BLOCKLEN);
    AES_Cipher((AES_state_t *) ej0, Ctx->RoundKey, Ctx->Mode);

    /* Prepare GHASH calculation. */
    memset(ghash_work, 0, sizeof(ghash_work));

    /* Compute GHASH for any AAD (additional authenticated data). */
    if (AAD) {
        p_data = (uint8_t *) (uintptr_t) AAD;
        data_len = AADLen;
        while (data_len) {
            memcpy(data_block, p_data, MIN(data_len, AES_BLOCKLEN));
            if (data_len < AES_BLOCKLEN)
                memset(data_block + data_len, 0, AES_BLOCKLEN - data_len);

            AES_BlockXor(ghash_work, data_block, ghash_work);
            AES_GCM_Mul(ghash_work, (AES_gcm_mul_table_t *) (uintptr_t) Ctx->Table);
            p_data += AES_BLOCKLEN;
            data_len -= MIN(data_len, AES_BLOCKLEN);
        }
    }

    /* Compute GHASH & Encrypt for any plaintext. */
    if (Data) {
        uint32_t ctr = 1;
        p_data = Data;
        data_len = DataLen;
        while (data_len) {
            ctr++;
            set_uint32_be(iv_block.bytes + 12, ctr);
            memcpy(aes_work, iv_block.bytes, sizeof(aes_work));
            AES_Cipher((AES_state_t *) aes_work, Ctx->RoundKey, Ctx->Mode);

            memcpy(data_block, p_data, MIN(data_len, AES_BLOCKLEN));
            AES_BlockXor(data_block, aes_work, data_block);
            if (data_len < AES_BLOCKLEN)
                memset(data_block + data_len, 0, AES_BLOCKLEN - data_len);

            memcpy(p_data, data_block, MIN(data_len, AES_BLOCKLEN));

            AES_BlockXor(ghash_work, data_block, ghash_work);
            AES_GCM_Mul(ghash_work, (AES_gcm_mul_table_t *) (uintptr_t) Ctx->Table);

            p_data += AES_BLOCKLEN;
            data_len -= MIN(data_len, AES_BLOCKLEN);
        }
    }
    /* Final GHASH calculation.
     * Add block that indicates lengths of AAD and plaintext. */
    memset(ghash_lengths.bytes, 0, AES_BLOCKLEN);
    set_uint32_be(ghash_lengths.bytes + 4, AADLen * 8u);
    set_uint32_be(ghash_lengths.bytes + 12, DataLen * 8u);
    AES_BlockXor(ghash_work, ghash_lengths.bytes, ghash_work);
    AES_GCM_Mul(ghash_work, (AES_gcm_mul_table_t *) (uintptr_t) Ctx->Table);

    /* XOR with pre-computed E(J₀). */
    AES_BlockXor(ghash_work, ej0, ghash_work);
    /* ghash_work now contains calculated tag. */
    if (Tag)
        memcpy(Tag, ghash_work, MIN(TagLen, AES_BLOCKLEN));
}

/**
 * @fn	bool AES_GCM_Decrypt(AES_GCM_Ctx_t* Ctx, uint8_t* Data, uint32_t DataLen, const uint8_t* AAD, uint32_t AADLen, const uint8_t* Tag, uint8_t TagLen)
 *
 * @brief	AES-GCM Encrypt.
 *
 * @param [in,out]	Ctx   	AES context.
 * @param [in,out]	Data   	Data to be decrypted.
 * @param 		  	DataLen	Data length.
 * @param [in]	    AAD   	Additional authenticated data.
 * @param 		  	AADLen	AAD length.
 * @param [out]	    Tag   	Authentication tag.
 * @param 		  	TagLen	Tag length.
 *
 * @retval  True if tag verified, otherwise false.
 */
bool AES_GCM_Decrypt(AES_GCM_Ctx_t *Ctx, uint8_t *Data, uint32_t DataLen, const uint8_t *AAD, uint32_t AADLen, const uint8_t *Tag, uint8_t TagLen) {
    AES_96b_iv_t iv_block;
    AES_gcm_lenhash_t ghash_lengths;
    uint8_t *p_data;
    uint32_t data_len;
    uint8_t data_block[AES_BLOCKLEN];
    uint8_t aes_work[AES_BLOCKLEN];
    uint8_t ghash_work[AES_BLOCKLEN];
    uint8_t ej0[AES_BLOCKLEN]; /* Pre-computed E(J₀) = AES(K, IV||0^31||1) */

    /* Prepare working IV. */
    memcpy(iv_block.bytes, Ctx->Iv, AES_GCM_IVLEN);
    set_uint32_be(iv_block.bytes + 12, 1);

    /* Pre-compute E(J₀) for final tag XOR. */
    memcpy(ej0, iv_block.bytes, AES_BLOCKLEN);
    AES_Cipher((AES_state_t *) ej0, Ctx->RoundKey, Ctx->Mode);

    /* Prepare GHASH calculation. */
    memset(ghash_work, 0, sizeof(ghash_work));

    /* Compute GHASH for any AAD (additional authenticated data). */
    if (AAD) {
        p_data = (uint8_t *) (uintptr_t) AAD;
        data_len = AADLen;
        while (data_len) {
            memcpy(data_block, p_data, MIN(data_len, AES_BLOCKLEN));
            if (data_len < AES_BLOCKLEN)
                memset(data_block + data_len, 0, AES_BLOCKLEN - data_len);

            AES_BlockXor(ghash_work, data_block, ghash_work);
            AES_GCM_Mul(ghash_work, (AES_gcm_mul_table_t *) (uintptr_t) Ctx->Table);
            p_data += AES_BLOCKLEN;
            data_len -= MIN(data_len, AES_BLOCKLEN);
        }
    }

    /* Compute GHASH for any ciphertext. */
    if (Data) {
        p_data = Data;
        data_len = DataLen;
        while (data_len) {
            memcpy(data_block, p_data, MIN(data_len, AES_BLOCKLEN));
            if (data_len < AES_BLOCKLEN)
                memset(data_block + data_len, 0, AES_BLOCKLEN - data_len);

            AES_BlockXor(ghash_work, data_block, ghash_work);
            AES_GCM_Mul(ghash_work, (AES_gcm_mul_table_t *) (uintptr_t) Ctx->Table);
            p_data += AES_BLOCKLEN;
            data_len -= MIN(data_len, AES_BLOCKLEN);
        }
    }
    /* Final GHASH calculation.
     * Add block that indicates lengths of AAD and plaintext. */
    memset(ghash_lengths.bytes, 0, AES_BLOCKLEN);
    set_uint32_be(ghash_lengths.bytes + 4, AADLen * 8u);
    set_uint32_be(ghash_lengths.bytes + 12, DataLen * 8u);
    AES_BlockXor(ghash_work, ghash_lengths.bytes, ghash_work);
    AES_GCM_Mul(ghash_work, (AES_gcm_mul_table_t *) (uintptr_t) Ctx->Table);

    /* XOR with pre-computed E(J₀). */
    AES_BlockXor(ghash_work, ej0, ghash_work);
    /* ghash_work now contains calculated tag. */

    /* Verify GHASH */
    if (memcmp(ghash_work, Tag, TagLen) != 0)
        return false;

    /* Decrypt any ciphertext. */
    if (Data) {
        uint32_t ctr = 1;
        p_data = Data;
        data_len = DataLen;
        while (data_len) {
            ctr++;
            set_uint32_be(iv_block.bytes + 12, ctr);
            memcpy(aes_work, iv_block.bytes, sizeof(aes_work));
            AES_Cipher((AES_state_t *) aes_work, Ctx->RoundKey, Ctx->Mode);

            memcpy(data_block, p_data, MIN(data_len, AES_BLOCKLEN));
            AES_BlockXor(data_block, aes_work, data_block);
            if (data_len < AES_BLOCKLEN)
                memset(data_block + data_len, 0, AES_BLOCKLEN - data_len);

            memcpy(p_data, data_block, MIN(data_len, AES_BLOCKLEN));

            p_data += AES_BLOCKLEN;
            data_len -= MIN(data_len, AES_BLOCKLEN);
        }
    }

    return true;
}

/**
 * @fn	static void AES_GCM_TableInit(AES_gcm_mul_table_t* Table, const uint8_t Key[AES_BLOCKLEN])
 *
 * @brief	Given a key, pre-calculate the medium-sized table that is needed for
 *          AES_GCM_Mul(), the 4-bit table-driven implementation of GCM multiplication.
 *
 * @param   Table GCM Table.
 * @param   Key 	AES key.
 */
static void AES_GCM_TableInit(AES_gcm_mul_table_t *Table, const uint8_t Key[AES_BLOCKLEN]) {
    AES_gcm_t a;
    AES_gcm_t block;
    uint_fast8_t i_bit = 0x80u;
    uint_fast8_t j;

    memset(Table, 0u, sizeof(*Table));
    AES_GCM_ByteToStruct(&a, Key);
    memcpy(block.bytes, Key, AES_BLOCKLEN);

    for (;;) {
        if (i_bit >= 0x10u) {
            for (j = 15u; j != 0u; j--) {
                if (j & (i_bit >> 4u)) {
                    AES_BlockXor(Table->keyDataHi[j - 1u].bytes, block.bytes, Table->keyDataHi[j - 1u].bytes);
                }
            }
        } else {
            for (j = 15u; j != 0u; j--) {
                if (j & i_bit) {
                    AES_BlockXor(Table->keyDataLo[j - 1u].bytes, block.bytes, Table->keyDataLo[j - 1u].bytes);
                }
            }
        }

        i_bit >>= 1u;
        if (i_bit == 0u)
            break;
        AES_GCM_GFMul2(&a);
        AES_GCM_StructToByte(block.bytes, &a);
    }
}

/**
 * @fn	static void AES_GCM_Mul(uint8_t Block[AES_BLOCKLEN], const AES_gcm_mul_table_t* Table)
 *
 * @brief	Galois 128-bit multiply.
 *
 * @param   Block AES key.
 * @param   Table GCM Table.
 */
static void AES_GCM_Mul(uint8_t Block[AES_BLOCKLEN], const AES_gcm_mul_table_t *Table) {
    uint8_t block_byte;
    uint8_t block_nibble;
    AES_gcm_t result = {{0}};
    uint_fast8_t i = AES_BLOCKLEN - 1u;

    /* Skip initial AES_GCM_GFMul256(&result) which is unnecessary when
     * result is initially zero. */
    goto start;

    while (1) {
        AES_GCM_GFMul256(&result);
    start:
        block_byte = Block[i];
        /* High nibble */
        block_nibble = (block_byte >> 4u) & 0xFu;
        if (block_nibble) {
            for (int j = 0; j < 4; j++) {
                result.element[j] ^= Table->keyDataHi[block_nibble - 1u].element[j];
            }
        }
        /* Low nibble */
        block_nibble = block_byte & 0xFu;
        if (block_nibble) {
            for (int j = 0; j < 4; j++) {
                result.element[j] ^= Table->keyDataLo[block_nibble - 1u].element[j];
            }
        }
        if (i == 0u) {
            break;
        }
        i--;
    }
    memcpy(Block, result.bytes, AES_BLOCKLEN);
}

/**
 * @fn	static void AES_GCM_ByteToStruct(AES_gcm_t* Dst, const uint8_t Src[AES_BLOCKLEN])
 *
 * @brief	Convert a multiplicand for GCM Galois 128-bit multiply into a form that can
 * b        e more efficiently manipulated for bit-by-bit calculation of the multiply.
 *
 * @param   Dst Destination struct.
 * @param   Src Data block.
 */
static void AES_GCM_ByteToStruct(AES_gcm_t *Dst, const uint8_t Src[AES_BLOCKLEN]) {
    uint_fast8_t i;
    uint_fast8_t j;
    const uint8_t *p_src_tmp;
    uint32_t temp;

    p_src_tmp = Src;
    for (i = 0; i < 4; i++) {
        temp = 0;
        for (j = 0; j < 4; j++) {
            temp = (temp << 8) | *p_src_tmp++;
        }
        Dst->element[i] = temp;
    }
}

/**
 * @fn	static void AES_GCM_StructToByte(uint8_t Dst[AES_BLOCKLEN], const AES_gcm_t* Src)
 *
 * @brief	Convert the GCM Galois 128-bit multiply special form back into an ordinary array of bytes.
 *
 * @param   Dst Destination data block.
 * @param   Src Source struct.
 */
static void AES_GCM_StructToByte(uint8_t Dst[AES_BLOCKLEN], const AES_gcm_t *Src) {
    uint_fast8_t i;
    uint_fast8_t j;
    uint8_t *p_dst_tmp;
    uint32_t temp;

    p_dst_tmp = Dst;
    for (i = 0; i < 4; i++) {
        temp = Src->element[i];
        for (j = 0; j < 4; j++) {
            *p_dst_tmp++ = (temp >> (32 - 8u));
            temp <<= 8;
        }
    }
}

/**
 * @fn	static void AES_GCM_GFMul2(AES_gcm_t* p)
 *
 * @brief	Galois 128-bit multiply by 2.
 *
 * @param   Data Data struct.
 */
static void AES_GCM_GFMul2(AES_gcm_t *Data) {
    uint_fast8_t i = 0;
    uint32_t carry;
    uint32_t next_carry;

    /*
     * This expression is intended to be timing invariant to prevent a timing
     * attack due to execution timing dependent on the bits of the GHASH key.
     * Check generated assembler from the compiler to confirm it.
     * This could be expressed as an 'if' statement, but then it's less likely
     * to be timing invariant.
     *
     * (0xE1u << (32 - 8u)) is the reduction poly bits.
     * (p->element[4 - 1u] & 1u) is the check of the MSbit
     * to determine if it's necessary to XOR the reduction poly.
     * (-(p->element[4 - 1u] & 1u)) turns it into a mask for
     * the bitwise AND.
     */
    carry = ((uint32_t) 0xE1u << (32 - 8u)) & (-(int32_t) (Data->element[4 - 1u] & 1u));

    goto start;
    for (; i < 4 - 1u; i++) {
        carry = next_carry;
    start:
        next_carry = ((Data->element[i] & 1u) << (32 - 1u));
        Data->element[i] = (Data->element[i] >> 1u) ^ carry;
    }
    Data->element[i] = (Data->element[i] >> 1u) ^ next_carry;
}

/**
 * @fn	static void AES_GCM_GFMul256(AES_gcm_t* p)
 *
 * @brief	Galois 128-bit multiply by 2^8.
 *
 * @param   Data Data struct.
 */
static void AES_GCM_GFMul256(AES_gcm_t *p) {
    uint_fast8_t i = 0;
    uint32_t carry;
    uint32_t next_carry;

    carry = AES_reduce_table[p->bytes[AES_BLOCKLEN - 1u]];

    goto start;
    for (; i < 4 - 1u; i++) {
        carry = next_carry;
    start:
        next_carry = p->element[i] >> (32 - 8u);
        p->element[i] = (p->element[i] << 8u) ^ carry;
    }
    p->element[i] = (p->element[i] << 8u) ^ next_carry;
}
