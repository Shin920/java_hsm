package com.nb.kms.hsm;

public class EventMsg {

    public static class KEY_TYPE
    {
        public static final int PRE_DEFINED_KEY = 0;
        public static final int K_MAC_KEY = 1;
        public static final int K_TRANS_KEY = 2;

    }

    public static class KEY_GEN_TYPE
    {
        public static final String preKey = "PREKEY";
        public static final String ktransKey1 = "KTRANS1";
        public static final String ktransKey2= "KTRANS2";
        public static final String kmacKey = "KMAC";
        public static final String masterKey = "MasterKey";

    }

    public static class HSM_MSG_TYPE {
        /* Msg Type 정의
         *
         *   CRUD, ENC/DEC, getKey(KCV)
         *
         *  */
        public static final int GENERATE_KEY = 0;
        public static final int CALCULATE_CBC = 1;
        public static final int COPY_KEY = 2;
        public static final int DELETE_KEY = 3;
        public static final int ENCRYPT_KEY = 4;
        public static final int DECRYPT_KEY = 5;
        public static final int GET_KCV = 6;
        public static final int GET_KEY = 7;
        public static final int GET_STATUS = 8;
        public static final int INJECT_KEY = 9;


    }


    public static class HSM_INFO {
        public static final long SLOT_ID = 0;
        public static final String PASSWORD = "0000";
        public static final String SO_PASSWORD = "9999";

    }


    public static class HSM_KEY_TYPE
    {
        public static final int RSA_TYPE = 0;
        public static final int DES_TYPE = 1;
        public static final int DES2_TYPE = 2;
        public static final int DES3_TYPE = 3;

    }

    public static class ERROR_CODE
    {
        public static final int RSA_TYPE = 0;
        public static final int DES_TYPE = 1;
        public static final int DES2_TYPE = 2;
        public static final int DES3_TYPE = 3;

    }

    public static class HSM_HEADER
    {
        public static final byte HEADER_TYPE_HSM = 0x00; /* HSM 패킷 */
        public static final byte HEADER_TYPE_WEB_APP = 0x01; /* WEB 패킷 */
        public static final byte HEADER_TYPE_DIST_APP = 0x02; /* DIST 패킷 */

    }

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

}
