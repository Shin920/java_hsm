package com.nb.kms.hsm;

import safenet.jcprov.*;
import safenet.jcprov.constants.*;
import com.nb.kms.hsm.EventMsg.*;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Date;

public class HsmService {

    private static HsmService instance;
    private CK_SESSION_HANDLE session = null;


    private HsmService() {
    }

    public static synchronized HsmService getInstance() {
        if (instance == null) {
            instance = new HsmService();
        }
        return instance;
    }

    public void generateKey(int keyType, String keyGenType, int serialNum, int etcsId) {

        boolean bPrivate = true;

        try {

            String KeyLabel = makeLabel(keyGenType, serialNum, etcsId);

            switch (keyType) {
                case HSM_KEY_TYPE.RSA_TYPE:
                    CK_OBJECT_HANDLE hPublicKey = new CK_OBJECT_HANDLE();
                    CK_OBJECT_HANDLE hPrivateKey = new CK_OBJECT_HANDLE();
                    generateAsymmetricKeyPair(CKM.RSA_PKCS_KEY_PAIR_GEN, keyType, KeyLabel, bPrivate, hPublicKey, hPrivateKey);
                    Logger.log("INFO", "RSA key pair (" + KeyLabel + ") generated. Public handle: " + hPublicKey.longValue() + ", Private handle: " + hPrivateKey.longValue());
                    break;
                case HSM_KEY_TYPE.DES_TYPE: {
                    CK_OBJECT_HANDLE hKey = new CK_OBJECT_HANDLE();
                    generateSymmetricKey(CKM.DES_KEY_GEN, keyType, KeyLabel, bPrivate, hKey);
                    Logger.log("INFO", "DES key (" + KeyLabel + ") generated. Handle: " + hKey.longValue());
                    break;
                }
                case HSM_KEY_TYPE.DES2_TYPE: {
                    CK_OBJECT_HANDLE hKey = new CK_OBJECT_HANDLE();
                    generateSymmetricKey(CKM.DES2_KEY_GEN, keyType, KeyLabel, bPrivate, hKey);
                    Logger.log("INFO", "DES2 key (" + KeyLabel + ") generated. Handle: " + hKey.longValue());
                    break;
                }
                case HSM_KEY_TYPE.DES3_TYPE: {
                    CK_OBJECT_HANDLE hKey = new CK_OBJECT_HANDLE();
                    generateSymmetricKey(CKM.DES3_KEY_GEN, keyType, KeyLabel, bPrivate, hKey);
                    Logger.log("INFO", "DES3 key (" + KeyLabel + ") generated. Handle: " + hKey.longValue());
                    break;
                }
                default:
                    Logger.log("ERROR", "Invalid key type: " + keyType);
                    break;
            }
        } catch (Exception ex) {
            Logger.error("Error generating key", ex);
        }
    }

    private void generateSymmetricKey(CK_MECHANISM_TYPE mechanismType, int keyType, String keyName, boolean bPrivate, CK_OBJECT_HANDLE hKey) throws CKR_Exception {
        CK_MECHANISM keyGenMech = new CK_MECHANISM(mechanismType);
        CK_ATTRIBUTE[] template = {
                new CK_ATTRIBUTE(CKA.KEY_TYPE, getKeyType(keyType)),
                new CK_ATTRIBUTE(CKA.CLASS, getKeyClass(keyType)),
                new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.TRUE),
                new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.FALSE),
                new CK_ATTRIBUTE(CKA.LABEL, keyName.getBytes()),
                new CK_ATTRIBUTE(CKA.PRIVATE, new CK_BBOOL(bPrivate))
        };
        CryptokiEx.C_GenerateKey(session, keyGenMech, template, template.length, hKey);
    }

    private void generateAsymmetricKeyPair(CK_MECHANISM_TYPE mechanismType, int keyType, String keyName, boolean bPrivate, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey) throws CKR_Exception {
        CK_MECHANISM keyGenMech = new CK_MECHANISM(mechanismType);
        CK_ATTRIBUTE[] publicTemplate = {
                new CK_ATTRIBUTE(CKA.KEY_TYPE, getKeyType(keyType)),
                new CK_ATTRIBUTE(CKA.CLASS, getKeyClass(keyType)),
                new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.TRUE),
                new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.FALSE),
                new CK_ATTRIBUTE(CKA.LABEL, keyName.getBytes()),
                new CK_ATTRIBUTE(CKA.PRIVATE, CK_BBOOL.FALSE)
        };
        CK_ATTRIBUTE[] privateTemplate = {
                new CK_ATTRIBUTE(CKA.KEY_TYPE, getKeyType(keyType)),
                new CK_ATTRIBUTE(CKA.CLASS, getKeyClass(keyType)),
                new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.TRUE),
                new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.TRUE),
                new CK_ATTRIBUTE(CKA.LABEL, keyName.getBytes()),
                new CK_ATTRIBUTE(CKA.PRIVATE, new CK_BBOOL(bPrivate))
        };
        CryptokiEx.C_GenerateKeyPair(session, keyGenMech, publicTemplate, publicTemplate.length, privateTemplate, privateTemplate.length, hPublicKey, hPrivateKey);
    }

    public void deleteKey(int keyType, String keyGenType, int serialNum, int etcsId) {
        boolean bPrivate = true;

        String KeyLabel = makeLabel(keyGenType, serialNum, etcsId);

        try {
            CK_OBJECT_HANDLE hKey = findKey(keyType, KeyLabel, bPrivate);
            if (hKey != null) {
                CryptokiEx.C_DestroyObject(session, hKey);
                Logger.log("INFO", "Key (" + KeyLabel + ") of type " + keyType + " deleted. Handle: " + hKey.longValue());
            } else {
                Logger.log("ERROR", "Key (" + KeyLabel + ") of type " + keyType + " not found.");
            }
        } catch (Exception ex) {
            Logger.error("Error deleting key", ex);
        }
    }

    private CK_OBJECT_HANDLE findKey(int keyType, String keyName, boolean bPrivate) throws CKR_Exception {

        CK_OBJECT_HANDLE[] foundObjects = {new CK_OBJECT_HANDLE()};

        LongRef objectCount = new LongRef();

        CK_ATTRIBUTE[] template = {
                new CK_ATTRIBUTE(CKA.CLASS, getKeyClass(keyType)),
                new CK_ATTRIBUTE(CKA.KEY_TYPE, getKeyType(keyType)),
                new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.TRUE),
                new CK_ATTRIBUTE(CKA.LABEL, keyName.getBytes()),
                new CK_ATTRIBUTE(CKA.PRIVATE, new CK_BBOOL(bPrivate))
        };

        try {
            // 세션 유효성 확인
            if (session == null) {
                System.err.println("세션 핸들이 null입니다.");
                return null;
            } else {

                // 세션 정보 확인
                CK_SESSION_INFO sessionInfo = new CK_SESSION_INFO();
                CryptokiEx.C_GetSessionInfo(session, sessionInfo);


                // 세션 상태 검증
                if ((sessionInfo.flags & CKF.SERIAL_SESSION) == 0 || (sessionInfo.flags & CKF.RW_SESSION) == 0) {
                    System.out.println("세션이 올바르게 설정되지 않았습니다. 세션 플래그: " + sessionInfo.flags);
                }
            }


            CryptokiEx.C_FindObjectsInit(session, template, template.length);

            CryptokiEx.C_FindObjects(session, foundObjects, foundObjects.length, objectCount);

            CryptokiEx.C_FindObjectsFinal(session);

            if (objectCount.value > 0) {
                System.out.println("핸들 값 확인: " + foundObjects[0]);

            } else {
                System.out.println("템플릿에 일치하는 객체를 찾을 수 없음");
            }


        } catch (Exception e) {
            System.err.println("PKCS#11 API 호출 중 예외 발생: " + e.getMessage());
        }
        return foundObjects[0];
    }


    //  핀 변경 함수 : 세션 핸들을 이미 확보한 상태에서 호출되므로, 슬롯 ID를 따로 받을 필요가 없음
    public void setPin(CK_SESSION_HANDLE session, String oldPin, String newPin) {

        try {

            CryptokiEx.C_SetPIN(session, oldPin.getBytes(), oldPin.length(), newPin.getBytes(), newPin.length());

        } catch (Exception e) {

            System.err.println("예외 발생: " + e.getMessage());

        }
    }

    public void initToken(long slotId, String pSoPin, String tokenLabel) {
        if (slotId <= 0 || pSoPin == null || tokenLabel == null) {
            throw new IllegalArgumentException("input data is null");
        }

        try {
            CryptokiEx.C_InitToken(slotId, pSoPin.getBytes(), tokenLabel.length(), tokenLabel.getBytes());
            CK_SESSION_HANDLE hSession = new CK_SESSION_HANDLE();
            CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, hSession);
            CryptokiEx.C_Login(hSession, CKU.SO, pSoPin.getBytes(), pSoPin.length());
            CryptokiEx.C_InitPIN(hSession, "defaultUserPin".getBytes(), "defaultUserPin".length());
            CryptokiEx.C_CloseSession(hSession);
        } catch (Exception e) {
            System.err.println("Token initialization failed: " + e.getMessage());
        }
    }


    public byte[] calculateKCV(int keyType, String keyGenType, int serialNum, int etcsId)
    {
        boolean bPrivate = true;

        String KeyLabel = makeLabel(keyGenType, serialNum, etcsId);

        try {
            CK_OBJECT_HANDLE hKey = findKey(keyType, KeyLabel, bPrivate);
            if (hKey == null) {
                Logger.log("ERROR", "Key (" + KeyLabel + ") of type " + keyType + " not found.");
                return null;
            }

            // KCV 계산을 위해서는 보통 0x0000000000000000을 암호화
            byte[] zeroBlock = new byte[8]; // 8 바이트 0x00으로 초기화된 블록


            //유동 메커니즘
            CK_MECHANISM mech = getKeyCalculateMech(keyType);

            byte[] encryptedBlock = new byte[8]; // 암호화된 결과를 받을 배열

            // C_EncryptInit 호출
            CryptokiEx.C_EncryptInit(session, mech, hKey);

            // C_Encrypt 호출
            LongRef encryptedLength = new LongRef();
            encryptedLength.value = encryptedBlock.length;
            CryptokiEx.C_Encrypt(session, zeroBlock, zeroBlock.length, encryptedBlock, encryptedLength);

            // KCV는 암호화된 첫 3바이트 또는 4바이트
            byte[] kcv = Arrays.copyOf(encryptedBlock, 3); // DES의 경우 첫 3바이트 사용

            Logger.log("INFO", "Key Check Value (KCV) for key (" + KeyLabel + "): " + bytesToHex(kcv));
            return kcv;

        } catch (Exception ex) {
            Logger.error("Error calculating KCV", ex);
            return null;
        }
    }


    public byte[] getPlainTextKey(int keyType, String keyGenType, int serialNum, int etcsId) {
        boolean bPrivate = true;

        String KeyLabel = makeLabel(keyGenType, serialNum, etcsId);

        try {
            CK_OBJECT_HANDLE hKey = findKey(keyType, KeyLabel, bPrivate);
            if (hKey == null) {
                Logger.log("ERROR", "Key (" + KeyLabel + ") of type " + keyType + " not found.");
                return null;
            }

            // 속성 가져오기: CKA_VALUE
            CK_ATTRIBUTE[] template = {
                    new CK_ATTRIBUTE(CKA.VALUE, new byte[24]) // 초기화 시 크기를 24바이트로 설정
            };

            // 속성 값을 가져옵니다.
            CryptokiEx.C_GetAttributeValue(session, hKey, template, template.length);

            // 평문 키 값 반환
            byte[] plainTextKey = (byte[]) template[0].pValue;

            // 평문 키 길이 체크 (필요 시)
            if (plainTextKey.length != 24) { // 예시로 24 바이트 체크
                Logger.log("ERROR", "Key Length is not 24-byte !!!");
                return null;
            }

            Logger.log("INFO", "Plaintext key (" + KeyLabel + ") retrieved successfully.");

            // 키의 각 바이트를 로깅
            StringBuilder keyHex = new StringBuilder();
            for (int i = 0; i < plainTextKey.length; i++) {
                keyHex.append(String.format("%02X ", plainTextKey[i])); // 각 바이트를 16진수로 변환하여 추가
            }
            Logger.log("INFO", "Plaintext key bytes: " + keyHex.toString().trim());

            return plainTextKey;

        } catch (Exception ex) {
            Logger.error("Error retrieving plaintext key", ex);
            return null;
        }
    }

    public byte[] encryptDataWithKey(String keyGenType, int keySerial, int myEtcsID, byte[] data) {
        try {
            //키 길이 24바이트 아니면 예외처리 or 리턴
            if(data.length != 24)
            {
                // 예외를 던지거나, 로깅 후 메서드 종료
                throw new IllegalArgumentException("Invalid key length: Key must be 24 bytes for 3DES.");
                // 또는
                // System.err.println("Invalid key length: Key must be 24 bytes.");
                // return;
            }
            // 키 라벨 생성
            String keyLabel = makeLabel(keyGenType, keySerial, myEtcsID);
            System.out.println("Generated key label: " + keyLabel);

            // 키 핸들을 찾기
            CK_OBJECT_HANDLE hKey = findKey(HSM_KEY_TYPE.DES3_TYPE, keyLabel, true);
            if (hKey == null) {
                Logger.log("ERROR", "Key (" + keyLabel + ") not found.");
                return null;
            }

            // 3DES 메커니즘 설정 (IV는 필요에 따라 설정)
            CK_MECHANISM mechanism = new CK_MECHANISM(CKM.DES3_CBC, new byte[8]);

            // 데이터 암호화 수행
            return encryptData(mechanism, hKey, data);

        } catch (Exception ex) {
            Logger.error("Error encrypting data with key: " + ex);
            return null;
        }
    }

    public byte[] decryptDataWithKey(String keyGenType, int keySerial, int myEtcsID, byte[] encryptedData) {
        try {
            // 키 라벨 생성
            String keyLabel = makeLabel(keyGenType, keySerial, myEtcsID);
            System.out.println("Generated key label: " + keyLabel);

            // 키 핸들을 찾기
            CK_OBJECT_HANDLE hKey = findKey(HSM_KEY_TYPE.DES3_TYPE, keyLabel, true);
            if (hKey == null) {
                Logger.log("ERROR", "Key (" + keyLabel + ") not found.");
                return null;
            }

            // 3DES 메커니즘 설정 (IV는 필요에 따라 설정)
            CK_MECHANISM mechanism = new CK_MECHANISM(CKM.DES3_CBC, new byte[8]);

            // 데이터 복호화 수행
            return decryptData(mechanism, hKey, encryptedData);

        } catch (Exception ex) {
            Logger.error("Error decrypting data with key: " + ex);
            return null;
        }
    }

    public byte[] encryptData(CK_MECHANISM encMechanism, CK_OBJECT_HANDLE hSecretKey, byte[] bInputData) {
        if (session == null || encMechanism == null || hSecretKey == null || bInputData == null) {
            throw new IllegalArgumentException("input data is null");
        }
        //키 길이 24바이트 아니면 예외처리 or 리턴
        if(bInputData.length != 24)
        {
            // 예외를 던지거나, 로깅 후 메서드 종료
            throw new IllegalArgumentException("Invalid key length: Key must be 24 bytes for 3DES.");
            // 또는
            // System.err.println("Invalid key length: Key must be 24 bytes.");
            // return;
        }

        byte[] bOutputData = null;

        try {
            CryptokiEx.C_EncryptInit(session, encMechanism, hSecretKey);
            LongRef encryptedLength = new LongRef();
            encryptedLength.value = bInputData.length;
            bOutputData = new byte[bInputData.length];
            CryptokiEx.C_Encrypt(session, bInputData, bInputData.length, bOutputData, encryptedLength);
        } catch (Exception e) {
            System.err.println("Encryption failed: " + e.getMessage());
        }

        return bOutputData;
    }

    public byte[] decryptData(CK_MECHANISM encMechanism, CK_OBJECT_HANDLE hSecretKey, byte[] bInputData) {
        if (session == null || encMechanism == null || hSecretKey == null || bInputData == null) {
            throw new IllegalArgumentException("input data is null");
        }
        //키 길이 24바이트 아니면 예외처리 or 리턴
        if(bInputData.length != 24)
        {
            // 예외를 던지거나, 로깅 후 메서드 종료
            throw new IllegalArgumentException("Invalid key length: Key must be 24 bytes for 3DES.");
            // 또는
            // System.err.println("Invalid key length: Key must be 24 bytes.");
            // return;
        }

        byte[] bOutputData = null;

        try {
            CryptokiEx.C_DecryptInit(session, encMechanism, hSecretKey);
            LongRef decryptedLength = new LongRef();
            decryptedLength.value = bInputData.length;
            bOutputData = new byte[bInputData.length];
            CryptokiEx.C_Decrypt(session, bInputData, bInputData.length, bOutputData, decryptedLength);
        } catch (Exception e) {
            System.err.println("Decryption failed: " + e.getMessage());
        }

        return bOutputData;
    }

    public byte[] calculateCBCMAC(String keyGenType, int keySerial, int myEtcsID, byte[] data) {
        try {
            // 키 라벨을 생성
            String keyLabel = makeLabel(keyGenType, keySerial, myEtcsID);
            System.out.println("Generated key label: " + keyLabel);

            // 키 핸들을 찾기
            CK_OBJECT_HANDLE hKey = findKey(HSM_KEY_TYPE.DES3_TYPE, keyLabel, true);
            if (hKey == null) {
                Logger.log("ERROR", "Key (" + keyLabel + ") not found.");
                return null;
            }

            // 평문 키 데이터를 가져오기
            byte[] plainKey = getPlainTextKey(HSM_KEY_TYPE.DES3_TYPE, keyGenType, keySerial, myEtcsID);
            if (plainKey == null || plainKey.length != 24) {
                Logger.log("ERROR", "Failed to retrieve a valid 3DES key.");
                return null;
            }

            // 평문 키를 3DES CBC-MAC 계산에 사용
            byte[] mac = calculate3DESCBCMAC(session, plainKey, data);
            Logger.log("INFO", "CBC-MAC calculated: " + bytesToHex(mac));

            return mac;

        } catch (Exception ex) {
            Logger.error("Error calculating CBC-MAC", ex);
            return null;
        }
    }

    private byte[] calculate3DESCBCMAC(CK_SESSION_HANDLE session, byte[] key, byte[] data) throws Exception {
        CK_MECHANISM mechanism = new CK_MECHANISM(CKM.DES_CBC, new byte[8]);

        // 3DES 키를 세 부분으로 나누기
        CK_OBJECT_HANDLE key1 = generateDESKey(session, Arrays.copyOfRange(key, 0, 8));
        CK_OBJECT_HANDLE key2 = generateDESKey(session, Arrays.copyOfRange(key, 8, 16));
        CK_OBJECT_HANDLE key3 = generateDESKey(session, Arrays.copyOfRange(key, 16, 24));

        byte[] previousBlock = new byte[8]; // 0으로 초기화된 블록
        int blockSize = 8;

        int numBlocks = (data.length + blockSize - 1) / blockSize; // 패딩 고려
        for (int i = 0; i < numBlocks; i++) {
            byte[] block = Arrays.copyOfRange(data, i * blockSize, Math.min((i + 1) * blockSize, data.length));

            // 블록이 8바이트 미만이면 패딩 추가
            if (block.length < blockSize) {
                block = Arrays.copyOf(block, blockSize);
                Arrays.fill(block, data.length - (i * blockSize), blockSize, (byte) 0);
            }

            byte[] xorBlock;
            if (i == 0) {
                xorBlock = xor(previousBlock, block); // 초기 벡터와 XOR
            } else {
                xorBlock = xor(previousBlock, block); // 이전 암호문과 XOR
            }

            // 암호화 수행
            if (i < numBlocks - 1) {
                CryptokiEx.C_EncryptInit(session, mechanism, key1);
                byte[] encryptedBlock = new byte[blockSize];
                LongRef encryptedBlockLen = new LongRef(blockSize);
                CryptokiEx.C_Encrypt(session, xorBlock, xorBlock.length, encryptedBlock, encryptedBlockLen);
                previousBlock = Arrays.copyOf(encryptedBlock, (int) encryptedBlockLen.value);
            } else {
                // 마지막 블록 처리
                CryptokiEx.C_EncryptInit(session, mechanism, key1);
                byte[] encryptedBlock = new byte[blockSize];
                LongRef encryptedBlockLen = new LongRef(blockSize);
                CryptokiEx.C_Encrypt(session, xorBlock, xorBlock.length, encryptedBlock, encryptedBlockLen);
                byte[] stage1 = Arrays.copyOf(encryptedBlock, (int) encryptedBlockLen.value);

                CryptokiEx.C_DecryptInit(session, mechanism, key2);
                byte[] decryptedBlock = new byte[blockSize];
                LongRef decryptedBlockLen = new LongRef(blockSize);
                CryptokiEx.C_Decrypt(session, stage1, stage1.length, decryptedBlock, decryptedBlockLen);
                byte[] stage2 = Arrays.copyOf(decryptedBlock, (int) decryptedBlockLen.value);

                CryptokiEx.C_EncryptInit(session, mechanism, key3);
                encryptedBlock = new byte[blockSize];
                encryptedBlockLen = new LongRef(blockSize);
                CryptokiEx.C_Encrypt(session, stage2, stage2.length, encryptedBlock, encryptedBlockLen);
                previousBlock = Arrays.copyOf(encryptedBlock, (int) encryptedBlockLen.value);
            }
        }

        return Arrays.copyOfRange(previousBlock, 0, blockSize);
    }

    private static CK_OBJECT_HANDLE generateDESKey(CK_SESSION_HANDLE session, byte[] keyValue) throws Exception {
        CK_ATTRIBUTE[] attributes = new CK_ATTRIBUTE[]{
                new CK_ATTRIBUTE(CKA.CLASS, CKO.SECRET_KEY),
                new CK_ATTRIBUTE(CKA.KEY_TYPE, CKK.DES),
                new CK_ATTRIBUTE(CKA.VALUE, keyValue),
                new CK_ATTRIBUTE(CKA.VALUE_LEN, keyValue.length),
                new CK_ATTRIBUTE(CKA.ENCRYPT, true),
                new CK_ATTRIBUTE(CKA.DECRYPT, true),
                new CK_ATTRIBUTE(CKA.TOKEN, false),
                new CK_ATTRIBUTE(CKA.SENSITIVE, true),
                new CK_ATTRIBUTE(CKA.PRIVATE, true)
        };

        CK_OBJECT_HANDLE hKey = new CK_OBJECT_HANDLE();
        CryptokiEx.C_CreateObject(session, attributes, attributes.length, hKey);
        return hKey;
    }

    public void copyKey(String keyGenType, int keySerial, int myEtcsID, int newKeySerial, int newEtcsType, String password) {
        try {
            // 원본 키 라벨을 생성
            String originalKeyLabel = makeLabel(keyGenType, keySerial, myEtcsID);

            // 원본 키 핸들을 찾기
            CK_OBJECT_HANDLE hOriginalKey = findKey(HSM_KEY_TYPE.DES3_TYPE, originalKeyLabel, !password.isEmpty());
            if (hOriginalKey == null) {
                Logger.error("Original key not found: " + originalKeyLabel);
                return;
            }

            // 새로운 키 라벨을 생성
            String newKeyLabel = makeLabel(keyGenType, newKeySerial, newEtcsType);

            // 원본 키를 복사할 때 사용할 템플릿
            CK_ATTRIBUTE[] newTemplate = {
                    new CK_ATTRIBUTE(CKA.LABEL, newKeyLabel.getBytes()),
                    new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.TRUE),
                    new CK_ATTRIBUTE(CKA.PRIVATE, CK_BBOOL.TRUE),
                    new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.FALSE)
            };

            // 키 복사 실행
            CK_OBJECT_HANDLE hNewKey = new CK_OBJECT_HANDLE();
            CryptokiEx.C_CopyObject(session, hOriginalKey, newTemplate, newTemplate.length, hNewKey);

            Logger.log("INFO", "Key copied from " + originalKeyLabel + " to " + newKeyLabel + ". New key handle: " + hNewKey.longValue());

        } catch (Exception ex) {
            Logger.error("Error copying key", ex);
        }
    }

    public void injectPrivateKey(int keyType, String keyGenType, int keySerial, int myEtcsID, byte[] privateKey) {

        //키 길이 24바이트 아니면 예외처리 or 리턴
        if(privateKey.length != 24)
        {
            // 예외를 던지거나, 로깅 후 메서드 종료
            throw new IllegalArgumentException("Invalid key length: Key must be 24 bytes for 3DES.");
            // 또는
            // System.err.println("Invalid key length: Key must be 24 bytes.");
            // return;
        }

        String keyLabel = makeLabel(keyGenType, keySerial, myEtcsID);

        try {

            // 1. 키 속성 설정 (privateKey는 CKA.VALUE에 설정)
            CK_ATTRIBUTE[] privateKeyTemplate = {
                    new CK_ATTRIBUTE(CKA.KEY_TYPE, getKeyType(keyType)),
                    new CK_ATTRIBUTE(CKA.CLASS, getKeyClass(keyType)),
                    new CK_ATTRIBUTE(CKA.LABEL, keyLabel.getBytes()),
                    new CK_ATTRIBUTE(CKA.VALUE, privateKey),  // 외부에서 전달된 키 데이터를 CKA.VALUE에 설정
                    new CK_ATTRIBUTE(CKA.VALUE_LEN, privateKey.length),
                    new CK_ATTRIBUTE(CKA.TOKEN, true),
                    new CK_ATTRIBUTE(CKA.SENSITIVE, false),
                    new CK_ATTRIBUTE(CKA.PRIVATE, true)
            };

            // 2. 키 주입
            CK_OBJECT_HANDLE hPrivateKey = new CK_OBJECT_HANDLE();
            CryptokiEx.C_CreateObject(session, privateKeyTemplate, privateKeyTemplate.length, hPrivateKey);

            System.out.println("개인 키가 HSM에 성공적으로 주입되었습니다. 키 핸들: " + hPrivateKey.longValue());

        } catch (CKR_Exception e) {
            System.err.println("키 주입 중 에러 발생: " + e.getMessage());
        }
    }

    public TokenInfo getHSMTokenInfo(long slotId) {
        try {
            CK_TOKEN_INFO tokenInfo = new CK_TOKEN_INFO();
            CryptokiEx.C_GetTokenInfo(slotId, tokenInfo);

            TokenInfo info = new TokenInfo();
            info.setLabel(new String(tokenInfo.label).trim());
            info.setManufacturerID(new String(tokenInfo.manufacturerID).trim());
            info.setModel(new String(tokenInfo.model).trim());
            info.setSerialNumber(new String(tokenInfo.serialNumber).trim());
            info.setFlags(tokenInfo.flags);
            info.setMaxSessionCount(tokenInfo.maxSessionCount);
            info.setSessionCount(tokenInfo.sessionCount);
            info.setMaxRwSessionCount(tokenInfo.maxRwSessionCount);
            info.setRwSessionCount(tokenInfo.rwSessionCount);
            info.setMaxPinLen(tokenInfo.maxPinLen);
            info.setMinPinLen(tokenInfo.minPinLen);
            info.setTotalPublicMemory(tokenInfo.totalPublicMemory);
            info.setFreePublicMemory(tokenInfo.freePublicMemory);
            info.setTotalPrivateMemory(tokenInfo.totalPrivateMemory);
            info.setFreePrivateMemory(tokenInfo.freePrivateMemory);
            info.setHardwareVersion(new TokenInfo.Version(tokenInfo.hardwareVersion.major, tokenInfo.hardwareVersion.minor));
            info.setFirmwareVersion(new TokenInfo.Version(tokenInfo.firmwareVersion.major, tokenInfo.firmwareVersion.minor));

            return info;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public SlotInfo getSlotInfo(long slotId) {
        CK_SLOT_INFO slotInfo = new CK_SLOT_INFO();
        CryptokiEx.C_GetSlotInfo(slotId, slotInfo);

        SlotInfo info = new SlotInfo();
        info.setSlotDescription(new String(slotInfo.slotDescription).trim());
        info.setManufacturerID(new String(slotInfo.manufacturerID).trim());
        info.setFlags(slotInfo.flags);
        info.setHardwareVersion(new SlotInfo.Version(slotInfo.hardwareVersion.major, slotInfo.hardwareVersion.minor));
        info.setFirmwareVersion(new SlotInfo.Version(slotInfo.firmwareVersion.major, slotInfo.firmwareVersion.minor));

        return info;
    }

    public String getHsmState() {
        StringBuilder output = new StringBuilder();
        String mode = "Unknown MODE";  // 초기값 설정

        try {
            Process process = Runtime.getRuntime().exec("hsmstate");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
                // "NORMAL MODE", "ERROR MODE" 등과 같은 상태를 찾음
                if (line.toUpperCase().contains("NORMAL MODE")) {
                    mode = "NORMAL MODE";
                } else if (line.toUpperCase().contains("ERROR MODE")) {
                    mode = "ERROR MODE";
                } else if (line.toUpperCase().contains("MAINTENANCE MODE")) {
                    mode = "MAINTENANCE MODE";
                }
                // 다른 모드들도 여기에 추가 가능
            }
            reader.close();
            process.waitFor();

            if (output.length() == 0) {
                Logger.error("hsmstate command returned no output.");
                return "HSM state retrieval failed or returned empty.";
            }

        } catch (IOException | InterruptedException e) {
            Logger.error("Error retrieving HSM state", e);
            return "Error retrieving HSM state: " + e.getMessage();
        }

        return mode;
    }

    public boolean checkNetworkConnectivity(String ip) {
        try {
            Process process = Runtime.getRuntime().exec("ping -c 1 " + ip); // Unix/Linux/MacOS용
            int returnVal = process.waitFor();
            return returnVal == 0; // ping 성공 시 true 반환
        } catch (IOException | InterruptedException e) {
            Logger.error("Ping failed for IP: " + ip, e);
            return false; // 실패 시 false 반환
        }
    }

    public HsmStatus getHsmStatusAndNetworkState(String ip) {
        // HSM 상태 확인
        String hsmState = getHsmState();

        if (hsmState == null || hsmState.isEmpty()) {
            Logger.error("HSM state retrieval failed or returned empty.");
            hsmState = "HSM state retrieval failed.";
        }

        // 네트워크 연결 상태 확인
        boolean networkConnected = checkNetworkConnectivity(ip);
        String networkStatus = networkConnected ? "Connected" : "Disconnected";

        // HsmStatus 객체로 반환
        return new HsmStatus(hsmState, networkStatus);
    }

    public boolean compareKCVWithDB(int keyType, String keyGenType, int serialNum, int etcsId, String dbKCV, String password) {
        // 원본 키의 KCV 계산
        byte[] calculatedKCV = calculateKCV(keyType, keyGenType, serialNum, etcsId);

        if (calculatedKCV == null) {
            Logger.log("ERROR", "Failed to calculate KCV.");
            return false;
        }

        // DB의 KCV와 비교
        if (bytesToHex(calculatedKCV).equals(dbKCV)) {
            Logger.log("INFO", "KCV matches for key (" + makeLabel(keyGenType, serialNum, etcsId) + ")");
            return true;
        } else {
            Logger.log("ERROR", "KCV mismatch for key (" + makeLabel(keyGenType, serialNum, etcsId) + ")");
            return false;
        }
    }



    private CKO getKeyClass(int keyType) {
        return switch (keyType) {
            case HSM_KEY_TYPE.DES_TYPE, HSM_KEY_TYPE.DES2_TYPE, HSM_KEY_TYPE.DES3_TYPE -> CKO.SECRET_KEY;
            case HSM_KEY_TYPE.RSA_TYPE -> CKO.PRIVATE_KEY;
            default -> throw new IllegalArgumentException("Invalid key type: " + keyType);
        };
    }

    private CKK getKeyType(int keyType) {

        return switch (keyType) {
            case HSM_KEY_TYPE.RSA_TYPE -> CKK.RSA;
            case HSM_KEY_TYPE.DES_TYPE -> CKK.DES;
            case HSM_KEY_TYPE.DES2_TYPE -> CKK.DES2;
            case HSM_KEY_TYPE.DES3_TYPE -> CKK.DES3;
            default -> throw new IllegalArgumentException("Invalid key type: " + keyType);
        };
    }

    private CK_MECHANISM getKeyCalculateMech(int keyType) {
        return switch (keyType) {
            case HSM_KEY_TYPE.DES_TYPE -> new CK_MECHANISM(CKM.DES_ECB);  // DES
            case HSM_KEY_TYPE.DES2_TYPE -> new CK_MECHANISM(CKM.DES3_ECB); // DES2
            case HSM_KEY_TYPE.DES3_TYPE -> new CK_MECHANISM(CKM.DES3_ECB); // DES3
            case HSM_KEY_TYPE.RSA_TYPE -> new CK_MECHANISM(CKM.RSA_PKCS);  // RSA
            default -> null;
        };

    }

    public String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public String makeLabel(String keyGenType, int keySerial, int myEtcsType) {
        String op = "#";
        String formedLabel = keyGenType + op + keySerial + op + myEtcsType;
        //System.out.println("formed_label: " + formedLabel);
        return formedLabel;
    }

    public static long makeSerial() {
        // 1. 현재 시간을 밀리초로 가져옴.
        long uid = new Date().getTime();

        // 2. 밀리초 값을 16진수 문자열로 변환.
        String hex = Long.toHexString(uid);

        // 3. 16진수 문자열의 3번째부터 10번째 문자까지 자름.
        String slicedHex = hex.substring(2, 10);
        System.out.println("hex.substring(2,10) : " + slicedHex);

        // 4. 잘라낸 문자열을 16진수로 해석하고 10진수로 변환.
        long result = Long.parseLong(slicedHex, 16);
        System.out.println("Long.parseLong(slicedHex, 16) : " + result);

        // 5. 결과 반환.
        return result;
    }

    public CK_SESSION_HANDLE getSessionHandle() {
        return session;
    }

    public void setSessionHandle(CK_SESSION_HANDLE session) {
        this.session = session;
    }

    private static byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }


}