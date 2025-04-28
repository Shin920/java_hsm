package Message.constant;

public class Offline
{
    public static final byte AUTH_ALGO_3DES = (byte)0x01;
    public static final byte OFFLINE_KMC_VERSION = (byte)0x01;

    /* KMC <-> KMC  ***************************************************************************************************************/

    public static class KM_SUBTYPE
    {
        /*  Deletion 요청, 응답 메시지 둘 다 해당 서브타입 값을 공유 */
        public static final byte DELETION_SUBTYPE_DELETE_REQUEST = 0b00000010;
        public static final byte DELETION_SUBTYPE_DELETE_NOTIFICATION = 0b00000100;
    }

    // 038
    public static class KM_REASON
    {
        public static final byte NEGACK_REASON_CBC_ERROR = 0b00000001;
        public static final byte NEGACK_REASON_UNKNOWN_ETCS_ID = 0b00000010;
        public static final byte NEGACK_REASON_KMAC_PARITY_ERROR = 0b00000011;

        public static final byte DELETION_TERMINATION_OF_SERVICE = 0b00000001;
        public static final byte DELETION_KMAC_CORRUPTION = 0b00000010;
    }

    // 038
    public static class OFFLINE_KM_MESSAGE
    {
        public static final byte KMAC_EXCHANGE = 0b00000100;
        public static final byte KMAC_DELETION = 0b00000110;
        public static final byte KMAC_UPDATE = 0b00010000;
        public static final byte CONF_KMAC_EXCHANGE = 0b00000101;
        public static final byte CONF_KMAC_DELETION = 0b00000111;
        public static final byte CONF_KMAC_UPDATE = 0b00010001;
        public static final byte KMAC_NEGACK = 0b00000000;
    }

    public static class KM_MESSAGE_IDX {
        public static final int FIST_IDX = 0;
        public static final int TR_QUANT_IDX = 0;
    }

    public static class KM_MESSAGE_SIZE {
        public static final int REASON_SIZE = 1;
        public static final int TR_QUANT_SIZE = 1;
        public static final int KM_MESSAGE_SIZE = 1;
        public static final int SUBTYPE_SIZE = 1;
        public static final int TNUM_SIZE = 1;
        public static final int ID_SIZE = 3;
        public static final int ISSUE_DATA_SIZE = 3;
        public static final int CBC_MAC_SIZE = 8;
        public static final int EFF_DATE_SIZE = 3;
        public static final int SNUM_SIZE = 3;
        public static final int KMAC_SIZE = 24;

        public static final int VALID_PERIOD_STRUCT_SIZE = 8;
        public static final int ETCS_STRUCT_SIZE = 4;
    }

    /* KMC <-> Entity  ***************************************************************************************************************/

    // 114
    public static class KEY_MESSAGE_AUTH_ALGO
    {
        public static final byte CRYPT_3DES_ECB = 0x01;
        public static final byte RESERVED = 0x02;
        public static final byte NDEFINED = 0x03;
    }

    // 114
    public static class OFFLINE_KEY_MESSAGE_TYPE
    {
        public static final byte KEY_MESSAGE_REPLACE_ALL_KEYS = 0x01;
        public static final byte KEY_MESSAGE_DELETE_ALL_KEYS = 0x02;
        public static final byte KEY_MESSAGE_ADD_AUTHENTICATION_KEY = 0x03;
        public static final byte KEY_MESSAGE_DELETE_KEY = 0x04;
        public static final byte KEY_MESSAGE_REPLACE_ETCS_ENTITIES = 0x05;       /* 0000 0101 */
        public static final byte KEY_MESSAGE_UPDATE_KEY_VALIDITY_PERIOD = 0x08;  /* 0000 1000 */
        public static final byte KEY_MESSAGE_INSTALL_TRANSPORT_KEY = 0x09;       /* 0000 1001 */
        public static final byte KEY_MESSAGE_RESPONSE_NOTIFY = 0x41;             /* 0100 0001 */
    }


    // 114
    public static class OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE
    {
        /* 요청이 성공적으로 처리되었습니다. */
        public static final byte RESPONSE_RESULT_REQUEST_SUCCESSFULLY_PROCESSED = 0; /* 성공 시 이 결과 코드로 응답 */
        /* 요청이 성공적으로 접수되었습니다 */
        public static final byte RESPONSE_RESULT_REQUEST_RECEIVED_SUCCESSFULLY = 1;
        /* MAC 코드 인증에 실패했습니다. */
        public static final byte RESPONSE_RESULT_AUTHENTICATION_OF_MAC_COD_HAS_FAILED = 2;
        /* 인증 알고리즘이 구현되지 않았습니다 */
        public static final byte RESPONSE_RESULT_AUTHENTICATION_ALGORITHM_NOT_IMPLEMENTED = 3;
        /* 전송 키를 찾을 수 없습니다.*/
        public static final byte RESPONSE_RESULT_TRANSPORT_KEY_NOT_FOUND = 4; /* 디코더에서는 고려하지 않음 */
        /* 복호화 알고리즘이 구현되지 않았습니다. */
        public static final byte RESPONSE_RESULT_DECRYPTION_ALGORITHM_NOT_IMPLEMENTATION = 5;
        /* 키를 찾을 수 없습니다. */
        public static final byte RESPONSE_RESULT_KEY_NOT_KNOW = 6; /* 디코더에서는 고려하지 않음 */
        /* 최대 키 수를 초과했습니다. */
        public static final byte RESPONSE_RESULT_MAXIMUM_NUMBER_OF_KEYS_EXCEEDED = 8;
        /* 최대 ETCS 엔터티 수를 초과했습니다.*/
        public static final byte RESPONSE_RESULT_MAXIMUM_NUMBER_OF_ETCS_ENTITIES_EXCEEDED = 9;
        /* 이미 정의된 ETCS 엔터티 키 입니다. */
        public static final byte RESPONSE_RESULT_KEY_ALREADY_DEFINED_IN_THE_ETCS_ENTITY = 10;
        /* 지원하지 않는 요청 */
        public static final byte RESPONSE_RESULT_REQUEST_NOT_SUPPORTED = 11;
        /* 수신된 요청에 불일치가 감지되었습니다. */
        public static final byte RESPONSE_RESULT_INCONSISTENCY_DETECTED_IN_THE_RECEIVED_REQUEST = 12;
        /* 메시지 길이 에러 */
        public static final byte RESPONSE_RESULT_MESSAGE_LENGTH_ERROR = 13;
        /* 홈 KMC 에서 요청하지 않은 이슈 입니다. */
        public static final byte RESPONSE_RESULT_REQUEST_NOT_ISSUED_BY_THE_HOME_KMC = 14;
        /* 요청이 잘못된 ETCS 엔터티로 전송되었습니다. */
        public static final byte RESPONSE_RESULT_REQUEST_SENT_TO_WRONG_ETCS_ENTITY = 15;
        /* 키 손상 (패리티 비트 또는 기타 키 관련 일관성 확인 실패)*/
        public static final byte RESPONSE_RESULT_KEY_CORRUPTED = 16; /* 디코더에서는 고려하지 않음 */
        /* 복구할 수 없는 키 저장소 문제 */
        public static final byte RESPONSE_RESULT_UNRECOVERABLE_KEY_STORE_ERROR = 17;
        /* 지원되지 않는 인터페이스 버전 */
        public static final byte RESPONSE_RESULT_INTERFACE_VERSION_NOT_SUPPORTED = 18;
        /* 위에 정의되지 않은 모든 에러에 사용 */
        public static final byte RESPONSE_RESULT_ETC_ERROR = 127;
    }

    // 114
    public static class KEY_TYPE
    {
        public static final byte KMAC = 0x01;
        public static final byte KTRANS = 0x02;
        public static final byte KMAC_KTRANS = 0x03;                 /* KMAC + KTRANS */
    }

    // 114 OFFLINE_KEY_MESSAGE_SIZE
    public static class OFFLINE_KEY_MESSAGE_SIZE {
        public static final int RESULT_SIZE = 1;
        public static final int LENGTH_FILED_SIZE = 1;
        public static final int E_ALGO_SIZE = 1;
        public static final int KT_NUM_SIZE = 4;
        public static final int K_NUM_SIZE = 2;
        public static final int KTRANS_SIZE = 48;
        public static final int KMAC_SIZE = 24;
        public static final int PEER_NUM_SIZE = 2;
        public static final int KEY_TYPE_SIZE = 1;
        public static final int LENGTH_SIZE = 4;
        public static final int TRANSACTION_SIZE = 4;
        public static final int SEQUENCE_SIZE = 2;
        public static final int SERIAL_SIZE = 4;
        public static final int VERSION_SIZE = 1;
        public static final int MSG_TYPE_SIZE = 1;
    }


}