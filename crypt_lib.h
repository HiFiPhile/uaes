/*
 * The MIT License (MIT)
 *
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

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef _CRYPT_LIB_H_
#define _CRYPT_LIB_H_
#ifdef __cplusplus
extern "C" {
#endif
/* Includes ------------------------------------------------------------------*/
#include <stdbool.h>
#include <stdint.h>
/* Exported defines --------------------------------------------------------- */
/* Block length in bytes AES is 128b block only */
#define AES_BLOCKLEN 16
/* Key length in bytes */
#define AES_KEYLEN_128 16
#define AES_KEYLEN_192 24
#define AES_KEYLEN_256 32
#define AES_KEYEXPLEN_128 176
#define AES_KEYEXPLEN_192 208
#define AES_KEYEXPLEN_256 240
#define AES_CTR_IVLEN 12
#define AES_GCM_IVLEN 12
#define AES_GCM_TABLELEN 480

#define AES_CTR_Encrypt(Ctx, Buf, Length) AES_CTR_Crypt(Ctx, Buf, Length)
#define AES_CTR_Decrypt(Ctx, Buf, Length) AES_CTR_Crypt(Ctx, Buf, Length)
/* Exported types ------------------------------------------------------------*/
/* AES Key length */
typedef enum AES_Mode_t {
    AES_Mode_128,
    AES_Mode_192,
    AES_Mode_256
} AES_Mode_t;
/* AES context */
typedef struct AES_Ctx_t {
    uint8_t RoundKey[AES_KEYEXPLEN_256];
    uint8_t Iv[AES_BLOCKLEN];
    AES_Mode_t Mode;
} AES_Ctx_t;
/* AES-GCM context */
typedef struct AES_GCM_Ctx_t {
    uint8_t Table[AES_GCM_TABLELEN];
    uint8_t RoundKey[AES_KEYEXPLEN_256];
    uint8_t Iv[AES_GCM_IVLEN];
    AES_Mode_t Mode;
} AES_GCM_Ctx_t;
/* AES CMAC context */
typedef struct AES_CMAC_Ctx_t {
    uint8_t K1[AES_KEYLEN_128];
    uint8_t K2[AES_KEYLEN_128];
    uint8_t RoundKey[AES_KEYEXPLEN_256];
    AES_Mode_t Mode;
} AES_CMAC_Ctx_t;
/* Exported constants --------------------------------------------------------*/
/* Exported macro ------------------------------------------------------------*/
/* Exported functions ------------------------------------------------------- */

/**
 * @fn	void AES_Init_Ctx(AES_Ctx_t* Ctx, const uint8_t* Key, AES_Mode_t Mode)
 *
 * @brief	AES initialize context.
 *
 * @param [in,out]	Ctx 	AES context.
 * @param 		  	Key 	AES key.
 * @param 		  	Mode	The mode.
 */
void AES_Init_Ctx(AES_Ctx_t *Ctx, const uint8_t *Key, AES_Mode_t Mode);

/**
 * @fn	void AES_GCM_Init_Ctx(AES_Ctx_t* Ctx, const uint8_t* Key, AES_Mode_t Mode)
 *
 * @brief	AES-GCM initialize context.
 *
 * @param [in,out]	Ctx 	AES context.
 * @param 		  	Key 	AES key.
 * @param 		  	Mode	The mode.
 */
void AES_GCM_Init_Ctx(AES_GCM_Ctx_t *Ctx, const uint8_t *Key, AES_Mode_t Mode);

/**
 * @fn	void AES_Init_Ctx_Iv(AES_Ctx_t* Ctx, const uint8_t* Key, const uint8_t* Iv, AES_Mode_t
 * Mode)
 *
 * @brief	AES initialize context and Iv.
 *
 * @param [in,out]	Ctx 	AES context.
 * @param 		  	Key 	AES key.
 * @param 		  	Iv  	Initial vector.
 * @param 		  	Mode	The mode.
 */
void AES_Init_Ctx_Iv(AES_Ctx_t *Ctx, const uint8_t *Key, const uint8_t *Iv, AES_Mode_t Mode);

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
void AES_GCM_Init_Ctx_Iv(AES_GCM_Ctx_t *Ctx, const uint8_t *Key, const uint8_t *Iv, AES_Mode_t Mode);

/**
 * @fn	void AES_Ctx_Set_Iv(AES_Ctx_t* Ctx, const uint8_t* Iv)
 *
 * @brief	AES set Iv.
 *
 * @param [in,out]	Ctx	AES context.
 * @param 		  	Iv 	Initial vector.
 */
void AES_Ctx_Set_Iv(AES_Ctx_t *Ctx, const uint8_t *Iv);

/**
 * @fn	void AES_GCM_Ctx_Set_Iv(AES_GCM_Ctx_t* Ctx, const uint8_t* Iv)
 *
 * @brief	AES-GCM set Iv.
 *
 * @param [in,out]	Ctx	AES context.
 * @param 		  	Iv 	Initial vector.
 */
void AES_GCM_Ctx_Set_Iv(AES_GCM_Ctx_t *Ctx, const uint8_t *Iv);

/**
 * @fn	void AES_Ctx_Set_Iv(AES_Ctx_t* Ctx, const uint8_t* Iv)
 *
 * @brief	AES-CTR set Iv, with 96b nonce / 32b counter.
 *
 * @param [in,out]	Ctx	AES context.
 * @param 		  	Iv 	Initial vector.
 */
void AES_CTR_Ctx_Set_Iv(AES_Ctx_t *Ctx, const uint8_t *Iv, uint32_t Ctr);

/**
 * @fn	void AES_CMAC_Init(AES_CMAC_Ctx_t* Ctx, const uint8_t* Key, AES_Mode_t Mode)
 *
 * @brief	AES-CMAC initialize context.
 *
 * @param [in,out]	Ctx 	AES context.
 * @param 		  	Key 	AES key.
 */
void AES_CMAC_Init(AES_CMAC_Ctx_t *Ctx, const uint8_t *Key, AES_Mode_t Mode);

/**
 * @fn	void AES_ECB_Encrypt(AES_Ctx_t* Ctx, uint8_t* Buf, uint32_t Length)
 *
 * @brief	AES ECB Encrypt.
 *
 * @param [in,out]	Ctx   	AES context.
 * @param [in,out]	Buf   	Data buffer.
 * @param 		  	Length	Data length.
 */
void AES_ECB_Encrypt(AES_Ctx_t *Ctx, uint8_t *Buf, uint32_t Length);

/**
 * @fn	void AES_ECB_Decrypt(AES_Ctx_t* Ctx, uint8_t* Buf, uint32_t Length)
 *
 * @brief	AES ECB Decrypt.
 *
 * @param [in,out]	Ctx   	AES context.
 * @param [in,out]	Buf   	Data buffer.
 * @param 		  	Length	Data length.
 */
void AES_ECB_Decrypt(AES_Ctx_t *Ctx, uint8_t *Buf, uint32_t Length);

/**
 * @fn	void AES_CBC_Encrypt(AES_Ctx_t* Ctx, uint8_t* Buf, uint32_t Length)
 *
 * @brief	AES CBC Encrypt.
 *
 * @param [in,out]	Ctx   	AES context.
 * @param [in,out]	Buf   	Data buffer.
 * @param 		  	Length	Data length.
 */
void AES_CBC_Encrypt(AES_Ctx_t *Ctx, uint8_t *Buf, uint32_t Length);

/**
 * @fn	void AES_CBC_Decrypt(AES_Ctx_t* Ctx, uint8_t* Buf, uint32_t Length)
 *
 * @brief	AES CBC Decrypt.
 *
 * @param [in,out]	Ctx   	AES context.
 * @param [in,out]	Buf   	Data buffer.
 * @param 		  	Length	Data length.
 */
void AES_CBC_Decrypt(AES_Ctx_t *Ctx, uint8_t *Buf, uint32_t Length);

/**
 * @fn	void AES_CTR_Crypt(AES_Ctx_t* Ctx, uint8_t* Buf, uint32_t Length)
 *
 * @brief	AES CTR Encrypt / Decrypt.
 *
 * @param [in,out]	Ctx   	AES context.
 * @param [in,out]	Buf   	Data buffer.
 * @param 		  	Length	Data length.
 */
void AES_CTR_Crypt(AES_Ctx_t *Ctx, uint8_t *Buf, uint32_t Length);

/**
 * @fn	void AES_CBC_Encrypt(AES_GCM_Ctx_t* Ctx, uint8_t* Data, uint32_t DataLen, const uint8_t* AAD, uint32_t AADLen, uint8_t* Tag, uint8_t TagLen)
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
void AES_GCM_Encrypt(AES_GCM_Ctx_t *Ctx, uint8_t *Data, uint32_t DataLen, const uint8_t *AAD, uint32_t AADLen, uint8_t *Tag, uint8_t TagLen);

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
bool AES_GCM_Decrypt(AES_GCM_Ctx_t *Ctx, uint8_t *Data, uint32_t DataLen, const uint8_t *AAD, uint32_t AADLen, const uint8_t *Tag, uint8_t TagLen);

/**
 * @fn	void AES_CMAC(AES_CMAC_Ctx_t* Ctx, const uint8_t* Data, uint32_t DataLen, uint8_t* Mac, uint_fast8_t MacLen)
 *
 * @brief	AES-CMAC Calculation.
 *
 * @param [in,out]	Ctx   	AES context.
 * @param       	Data   	Input buffer.
 * @param 		  	DataLen	Data length.
 * @param       	Mac   	Mac buffer.
 * @param 		  	MacLen	Mac length.
 */
void AES_CMAC(AES_CMAC_Ctx_t *Ctx, const uint8_t *Data, uint32_t DataLen, uint8_t *Mac, uint_fast8_t MacLen);

#ifdef __cplusplus
}
#endif
#endif
