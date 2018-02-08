/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * Copyright (C) 2010 Stefan Walter
 * Copyright (C) 2011 Collabora Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, see
 * <http://www.gnu.org/licenses/>.
 *
 * In addition, when the library is used with OpenSSL, a special
 * exception applies. Refer to the LICENSE_EXCEPTION file for details.
 */

#include <glib.h>

#include <p11-kit/pkcs11.h>

#include "pkcs11/gpkcs11array.h"

#ifndef MOCK_MODULE_H
#define MOCK_MODULE_H

extern CK_FUNCTION_LIST mock_default_functions;

CK_RV               mock_C_Initialize                          (CK_VOID_PTR pInitArgs);

CK_RV               mock_validate_and_C_Initialize             (CK_VOID_PTR pInitArgs);

CK_RV               mock_C_Finalize                            (CK_VOID_PTR pReserved);

CK_RV               mock_C_GetInfo                             (CK_INFO_PTR pInfo);

CK_RV               mock_C_GetFunctionList                     (CK_FUNCTION_LIST_PTR_PTR list);

CK_RV               mock_C_GetSlotList                         (CK_BBOOL tokenPresent,
                                                                CK_SLOT_ID_PTR pSlotList,
                                                                CK_ULONG_PTR pulCount);

CK_RV               mock_C_GetSlotInfo                         (CK_SLOT_ID slotID,
                                                                CK_SLOT_INFO_PTR pInfo);

CK_RV               mock_C_GetTokenInfo                        (CK_SLOT_ID slotID,
                                                                CK_TOKEN_INFO_PTR pInfo);

CK_RV               mock_fail_C_GetTokenInfo                   (CK_SLOT_ID slotID,
                                                                CK_TOKEN_INFO_PTR pInfo);

CK_RV               mock_C_GetMechanismList                    (CK_SLOT_ID slotID,
                                                                CK_MECHANISM_TYPE_PTR pMechanismList,
                                                                CK_ULONG_PTR pulCount);

CK_RV               mock_C_GetMechanismInfo                    (CK_SLOT_ID slotID,
                                                                CK_MECHANISM_TYPE type,
                                                                CK_MECHANISM_INFO_PTR pInfo);

CK_RV               mock_specific_args_C_InitToken             (CK_SLOT_ID slotID,
                                                                CK_UTF8CHAR_PTR pPin,
                                                                CK_ULONG ulPinLen,
                                                                CK_UTF8CHAR_PTR pLabel);

CK_RV               mock_unsupported_C_WaitForSlotEvent        (CK_FLAGS flags,
                                                                CK_SLOT_ID_PTR pSlot,
                                                                CK_VOID_PTR pReserved);

CK_RV               mock_C_OpenSession                         (CK_SLOT_ID slotID,
                                                                CK_FLAGS flags,
                                                                CK_VOID_PTR pApplication,
                                                                CK_NOTIFY Notify,
                                                                CK_SESSION_HANDLE_PTR phSession);

CK_RV               mock_fail_C_OpenSession                    (CK_SLOT_ID slotID,
                                                                CK_FLAGS flags,
                                                                CK_VOID_PTR pApplication,
                                                                CK_NOTIFY Notify,
                                                                CK_SESSION_HANDLE_PTR phSession);

CK_RV               mock_C_CloseSession                        (CK_SESSION_HANDLE hSession);

CK_RV               mock_C_CloseAllSessions                    (CK_SLOT_ID slotID);

CK_RV               mock_C_GetFunctionStatus                   (CK_SESSION_HANDLE hSession);

CK_RV               mock_C_CancelFunction                      (CK_SESSION_HANDLE hSession);

CK_RV               mock_C_GetSessionInfo                      (CK_SESSION_HANDLE hSession,
                                                                CK_SESSION_INFO_PTR pInfo);

CK_RV               mock_fail_C_GetSessionInfo                 (CK_SESSION_HANDLE hSession,
                                                                CK_SESSION_INFO_PTR pInfo);

CK_RV               mock_C_InitPIN                             (CK_SESSION_HANDLE hSession,
                                                                CK_UTF8CHAR_PTR pPin,
                                                                CK_ULONG ulPinLen);

CK_RV               mock_C_SetPIN                              (CK_SESSION_HANDLE hSession,
                                                                CK_UTF8CHAR_PTR pOldPin,
                                                                CK_ULONG ulOldLen,
                                                                CK_UTF8CHAR_PTR pNewPin,
                                                                CK_ULONG ulNewLen);

CK_RV               mock_unsupported_C_GetOperationState       (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pOperationState,
                                                                CK_ULONG_PTR pulOperationStateLen);

CK_RV               mock_unsupported_C_SetOperationState       (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pOperationState,
                                                                CK_ULONG ulOperationStateLen,
                                                                CK_OBJECT_HANDLE hEncryptionKey,
                                                                CK_OBJECT_HANDLE hAuthenticationKey);

CK_RV               mock_C_Login                               (CK_SESSION_HANDLE hSession,
                                                                CK_USER_TYPE userType,
                                                                CK_UTF8CHAR_PTR pPin,
                                                                CK_ULONG pPinLen);

CK_RV               mock_C_Logout                              (CK_SESSION_HANDLE hSession);

CK_RV               mock_C_CreateObject                        (CK_SESSION_HANDLE hSession,
                                                                CK_ATTRIBUTE_PTR pTemplate,
                                                                CK_ULONG ulCount,
                                                                CK_OBJECT_HANDLE_PTR phObject);

CK_RV               mock_fail_C_CreateObject                   (CK_SESSION_HANDLE hSession,
                                                                CK_ATTRIBUTE_PTR pTemplate,
                                                                CK_ULONG ulCount,
                                                                CK_OBJECT_HANDLE_PTR phObject);

CK_RV               mock_unsupported_C_CopyObject              (CK_SESSION_HANDLE hSession,
                                                                CK_OBJECT_HANDLE hObject,
                                                                CK_ATTRIBUTE_PTR pTemplate,
                                                                CK_ULONG ulCount,
                                                                CK_OBJECT_HANDLE_PTR phNewObject);

CK_RV               mock_C_DestroyObject                       (CK_SESSION_HANDLE hSession,
                                                                CK_OBJECT_HANDLE hObject);

CK_RV               mock_unsupported_C_GetObjectSize           (CK_SESSION_HANDLE hSession,
                                                                CK_OBJECT_HANDLE hObject,
                                                                CK_ULONG_PTR pulSize);

CK_RV               mock_C_GetAttributeValue                   (CK_SESSION_HANDLE hSession,
                                                                CK_OBJECT_HANDLE hObject,
                                                                CK_ATTRIBUTE_PTR pTemplate,
                                                                CK_ULONG ulCount);

CK_RV               mock_fail_C_GetAttributeValue              (CK_SESSION_HANDLE hSession,
                                                                CK_OBJECT_HANDLE hObject,
                                                                CK_ATTRIBUTE_PTR pTemplate,
                                                                CK_ULONG ulCount);

CK_RV               mock_C_SetAttributeValue                   (CK_SESSION_HANDLE hSession,
                                                                CK_OBJECT_HANDLE hObject,
                                                                CK_ATTRIBUTE_PTR pTemplate,
                                                                CK_ULONG ulCount);

CK_RV               mock_C_FindObjectsInit                     (CK_SESSION_HANDLE hSession,
                                                                CK_ATTRIBUTE_PTR pTemplate,
                                                                CK_ULONG ulCount);

CK_RV               mock_C_FindObjects                         (CK_SESSION_HANDLE hSession,
                                                                CK_OBJECT_HANDLE_PTR phObject,
                                                                CK_ULONG ulMaxObjectCount,
                                                                CK_ULONG_PTR pulObjectCount);

CK_RV               mock_fail_C_FindObjects                    (CK_SESSION_HANDLE hSession,
                                                                CK_OBJECT_HANDLE_PTR phObject,
                                                                CK_ULONG ulMaxObjectCount,
                                                                CK_ULONG_PTR pulObjectCount);

CK_RV               mock_C_FindObjectsFinal                    (CK_SESSION_HANDLE hSession);

CK_RV               mock_no_mechanisms_C_EncryptInit           (CK_SESSION_HANDLE hSession,
                                                                CK_MECHANISM_PTR pMechanism,
                                                                CK_OBJECT_HANDLE hKey);

CK_RV               mock_not_initialized_C_Encrypt             (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pData,
                                                                CK_ULONG ulDataLen,
                                                                CK_BYTE_PTR pEncryptedData,
                                                                CK_ULONG_PTR pulEncryptedDataLen);

CK_RV               mock_unsupported_C_EncryptUpdate           (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pPart,
                                                                CK_ULONG ulPartLen,
                                                                CK_BYTE_PTR pEncryptedPart,
                                                                CK_ULONG_PTR pulEncryptedPartLen);

CK_RV               mock_unsupported_C_EncryptFinal            (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pLastEncryptedPart,
                                                                CK_ULONG_PTR pulLastEncryptedPartLen);

CK_RV               mock_no_mechanisms_C_DecryptInit           (CK_SESSION_HANDLE hSession,
                                                                CK_MECHANISM_PTR pMechanism,
                                                                CK_OBJECT_HANDLE hKey);

CK_RV               mock_not_initialized_C_Decrypt             (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pEncryptedData,
                                                                CK_ULONG ulEncryptedDataLen,
                                                                CK_BYTE_PTR pData,
                                                                CK_ULONG_PTR pulDataLen);

CK_RV               mock_unsupported_C_DecryptUpdate           (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pEncryptedPart,
                                                                CK_ULONG ulEncryptedPartLen,
                                                                CK_BYTE_PTR pPart,
                                                                CK_ULONG_PTR pulPartLen);

CK_RV               mock_unsupported_C_DecryptFinal            (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pLastPart,
                                                                CK_ULONG_PTR pulLastPartLen);

CK_RV               mock_unsupported_C_DigestInit              (CK_SESSION_HANDLE hSession,
                                                                CK_MECHANISM_PTR pMechanism);

CK_RV               mock_unsupported_C_Digest                  (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pData,
                                                                CK_ULONG ulDataLen,
                                                                CK_BYTE_PTR pDigest,
                                                                CK_ULONG_PTR pulDigestLen);

CK_RV               mock_unsupported_C_DigestUpdate            (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pPart,
                                                                CK_ULONG ulPartLen);

CK_RV               mock_unsupported_C_DigestKey               (CK_SESSION_HANDLE hSession,
                                                                CK_OBJECT_HANDLE hKey);

CK_RV               mock_unsupported_C_DigestFinal             (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pDigest,
                                                                CK_ULONG_PTR pulDigestLen);

CK_RV               mock_no_mechanisms_C_SignInit              (CK_SESSION_HANDLE hSession,
                                                                CK_MECHANISM_PTR pMechanism,
                                                                CK_OBJECT_HANDLE hKey);

CK_RV               mock_not_initialized_C_Sign                (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pData,
                                                                CK_ULONG ulDataLen,
                                                                CK_BYTE_PTR pSignature,
                                                                CK_ULONG_PTR pulSignatureLen);

CK_RV               mock_unsupported_C_SignUpdate              (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pPart,
                                                                CK_ULONG ulPartLen);

CK_RV               mock_unsupported_C_SignFinal               (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pSignature,
                                                                CK_ULONG_PTR pulSignatureLen);

CK_RV               mock_unsupported_C_SignRecoverInit         (CK_SESSION_HANDLE hSession,
                                                                CK_MECHANISM_PTR pMechanism,
                                                                CK_OBJECT_HANDLE hKey);

CK_RV               mock_unsupported_C_SignRecover             (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pData,
                                                                CK_ULONG ulDataLen,
                                                                CK_BYTE_PTR pSignature,
                                                                CK_ULONG_PTR pulSignatureLen);

CK_RV               mock_no_mechanisms_C_VerifyInit            (CK_SESSION_HANDLE hSession,
                                                                CK_MECHANISM_PTR pMechanism,
                                                                CK_OBJECT_HANDLE hKey);

CK_RV               mock_not_initialized_C_Verify              (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pData,
                                                                CK_ULONG ulDataLen,
                                                                CK_BYTE_PTR pSignature,
                                                                CK_ULONG ulSignatureLen);

CK_RV               mock_unsupported_C_VerifyUpdate            (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pPart,
                                                                CK_ULONG ulPartLen);

CK_RV               mock_unsupported_C_VerifyFinal             (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pSignature,
                                                                CK_ULONG pulSignatureLen);

CK_RV               mock_unsupported_C_VerifyRecoverInit       (CK_SESSION_HANDLE hSession,
                                                                CK_MECHANISM_PTR pMechanism,
                                                                CK_OBJECT_HANDLE hKey);

CK_RV               mock_unsupported_C_VerifyRecover           (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pSignature,
                                                                CK_ULONG pulSignatureLen,
                                                                CK_BYTE_PTR pData,
                                                                CK_ULONG_PTR pulDataLen);

CK_RV               mock_unsupported_C_DigestEncryptUpdate     (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pPart,
                                                                CK_ULONG ulPartLen,
                                                                CK_BYTE_PTR pEncryptedPart,
                                                                CK_ULONG_PTR ulEncryptedPartLen);

CK_RV               mock_unsupported_C_DecryptDigestUpdate     (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pEncryptedPart,
                                                                CK_ULONG ulEncryptedPartLen,
                                                                CK_BYTE_PTR pPart,
                                                                CK_ULONG_PTR pulPartLen);

CK_RV               mock_unsupported_C_SignEncryptUpdate       (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pPart,
                                                                CK_ULONG ulPartLen,
                                                                CK_BYTE_PTR pEncryptedPart,
                                                                CK_ULONG_PTR ulEncryptedPartLen);

CK_RV               mock_unsupported_C_DecryptVerifyUpdate     (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pEncryptedPart,
                                                                CK_ULONG ulEncryptedPartLen,
                                                                CK_BYTE_PTR pPart,
                                                                CK_ULONG_PTR pulPartLen);

CK_RV               mock_unsupported_C_GenerateKey             (CK_SESSION_HANDLE hSession,
                                                                CK_MECHANISM_PTR pMechanism,
                                                                CK_ATTRIBUTE_PTR pTemplate,
                                                                CK_ULONG ulCount,
                                                                CK_OBJECT_HANDLE_PTR phKey);

CK_RV               mock_no_mechanisms_C_GenerateKeyPair         (CK_SESSION_HANDLE hSession,
                                                                CK_MECHANISM_PTR pMechanism,
                                                                CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                                                CK_ULONG ulPublicKeyAttributeCount,
                                                                CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                                                CK_ULONG ulPrivateKeyAttributeCount,
                                                                CK_OBJECT_HANDLE_PTR phPublicKey,
                                                                CK_OBJECT_HANDLE_PTR phPrivateKey);

CK_RV               mock_no_mechanisms_C_WrapKey                 (CK_SESSION_HANDLE hSession,
                                                                CK_MECHANISM_PTR pMechanism,
                                                                CK_OBJECT_HANDLE hWrappingKey,
                                                                CK_OBJECT_HANDLE hKey,
                                                                CK_BYTE_PTR pWrappedKey,
                                                                CK_ULONG_PTR pulWrappedKeyLen);

CK_RV               mock_no_mechanisms_C_UnwrapKey               (CK_SESSION_HANDLE hSession,
                                                                CK_MECHANISM_PTR pMechanism,
                                                                CK_OBJECT_HANDLE pUnwrappingKey,
                                                                CK_BYTE_PTR pWrappedKey,
                                                                CK_ULONG pulWrappedKeyLen,
                                                                CK_ATTRIBUTE_PTR pTemplate,
                                                                CK_ULONG ulCount,
                                                                CK_OBJECT_HANDLE_PTR phKey);

CK_RV               mock_no_mechanisms_C_DeriveKey               (CK_SESSION_HANDLE hSession,
                                                                CK_MECHANISM_PTR pMechanism,
                                                                CK_OBJECT_HANDLE hBaseKey,
                                                                CK_ATTRIBUTE_PTR pTemplate,
                                                                CK_ULONG ulCount,
                                                                CK_OBJECT_HANDLE_PTR phKey);

CK_RV               mock_unsupported_C_SeedRandom              (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pSeed,
                                                                CK_ULONG ulSeedLen);

CK_RV               mock_unsupported_C_GenerateRandom          (CK_SESSION_HANDLE hSession,
                                                                CK_BYTE_PTR pRandomData,
                                                                CK_ULONG ulRandomLen);

CK_OBJECT_HANDLE    mock_module_find_object                    (CK_SESSION_HANDLE session,
                                                                CK_ATTRIBUTE_PTR attrs,
                                                                CK_ULONG n_attrs);

guint               mock_module_count_objects                  (CK_SESSION_HANDLE session);

typedef gboolean    (*MockEnumerator)                          (CK_OBJECT_HANDLE handle,
                                                                GPkcs11Array *attrs,
                                                                gpointer user_data);

void                mock_module_enumerate_objects              (CK_SESSION_HANDLE session,
                                                                MockEnumerator func,
                                                                gpointer user_data);

CK_OBJECT_HANDLE    mock_module_take_object                    (GPkcs11Array *attrs);

void                mock_module_set_object                     (CK_OBJECT_HANDLE object,
                                                                CK_ATTRIBUTE_PTR attrs,
                                                                CK_ULONG n_attrs);

void                mock_module_set_pin                        (const gchar *password);

#define MOCK_SLOT_ONE_ID  52
#define MOCK_SLOT_TWO_ID  134

#define MOCK_SLOT_ONE_PIN "booo"
#define MOCK_SLOT_ONE_URI "pkcs11:manufacturer=TEST%20MANUFACTURER;serial=TEST%20SERIAL"

#endif /* MOCK_MODULE_H */
