import safenet.jcprov.*;
import safenet.jcprov.constants.*;
import java.util.Arrays;

public class TripleDESCBCMACExample {

    private static CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();

    // 고정된 키 값
    private static final byte[] aTestKMAC = {
            0x01, 0x02, 0x04, 0x07, 0x08, 0x0B, 0x0D, 0x0E,
            0x10, 0x13, 0x15, 0x16, 0x19, 0x1A, 0x1C, 0x1F,
            0x20, 0x23, 0x25, 0x26, 0x29, 0x2A, 0x2C, 0x2F
    };

    public static void main(String[] args) {
        try {
            byte[] data = {0x01, 0x01, 0x01, 0x56, 0x01, 0x01, (byte) 0xdd, (byte) 0xc0,
                    0x27, 0x05, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00,
                    0x2A, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
                    0x09, 0x30, 0x00, 0x00, 0x00, 0x01, 0x57, (byte) 0xEC,
                    (byte) 0xc8, (byte) 0xd3, 0x7A, (byte) 0xf1, 0x4C, 0x7F, (byte) 0x89, (byte) 0x94,
                    (byte) 0xB0, (byte) 0xE9, 0x49, 0x73, 0x3B, 0x0E, 0x3B, (byte) 0x83,
                    (byte) 0xA2, 0x32, 0x10, (byte) 0xEC, (byte) 0xAB, (byte) 0xE6, 0x49, 0x4A,
                    (byte) 0x97, (byte) 0xC4, 0x7A, 0x7F, 0x2A, 0x73, 0x1A, (byte) 0xD6,
                    0x38, 0x57, 0x6B, 0x38, (byte) 0xDA, (byte) 0xA2, (byte) 0xD0, (byte) 0xB3,
                    (byte) 0xE6, 0x57, (byte) 0x9E, 0x25, 0x38, 0x25, 0x00, 0x00};

            // CryptokiEx 라이브러리 초기화 및 세션 열기
            CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));
            long slotId = 0;
            String password = "0000";
            CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION, null, null, session);

            // 사용자 로그인
            CryptokiEx.C_Login(session, CKU.USER, password.getBytes(), password.length());

            // 3DES 키 생성 (고정된 값 사용)
            CK_OBJECT_HANDLE key1 = generateDESKey(session, Arrays.copyOfRange(aTestKMAC, 0, 8));
            CK_OBJECT_HANDLE key2 = generateDESKey(session, Arrays.copyOfRange(aTestKMAC, 8, 16));
            CK_OBJECT_HANDLE key3 = generateDESKey(session, Arrays.copyOfRange(aTestKMAC, 16, 24));

            // 3DES CBC-MAC 계산
            byte[] mac = calculate3DESCBCMAC(session, key1, key2, key3, data);
            System.out.println("최종 3DES CBC-MAC: " + bytesToHex(mac));

            // 세션 닫기 및 종료
            CryptokiEx.C_Logout(session);
            CryptokiEx.C_CloseSession(session);
            CryptokiEx.C_Finalize(null);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 3DES CBC-MAC 계산 함수
    public static byte[] calculate3DESCBCMAC(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key1, CK_OBJECT_HANDLE key2, CK_OBJECT_HANDLE key3, byte[] data) throws Exception {
        CK_MECHANISM mechanism = new CK_MECHANISM(CKM.DES_CBC, new byte[8]);

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

    // 3DES 키 생성 함수 (고정된 값 사용)
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

    // XOR 연산 함수
    private static byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    // 바이트 배열을 16진수 문자열로 변환하는 유틸리티 메서드
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}