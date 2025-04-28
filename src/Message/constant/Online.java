package Message.constant;

public class Online
{
    // online
    public static final byte ONLINE_VERSION = 1;
    public static final byte ONLINE_INTERFACE_VERSION = 2;

    // 137
    public static class KEY_MESSAGE_PARSING_RESULT_ACTION
    {
        public static final byte PARSING_RESULT_ACTION_NONE = 0;
        public static final byte PARSING_RESULT_ACTION_RESPONSE = 1;
        public static final byte PARSING_RESULT_ACTION_IGNORED = 2;
        public static final byte PARSING_RESULT_ACTION_CONNECTION_FINISHED = 3;
    }

    // 137
    public static class ONLINE_KEY_MESSAGE_TYPE
    {
        public static final byte CMD_ADD_KEYS = 0;
        public static final byte CMD_DELETE_KEYS = 1;
        public static final byte CMD_DELETE_ALL_KEYS = 2;
        public static final byte CMD_UPDATE_KEY_VALIDITIES = 3;
        public static final byte CMD_UPDATE_KEY_ENTITIES = 4;
        public static final byte CMD_REQUEST_KEY_OPERATION = 5;
        public static final byte INQ_REQUEST_KEY_DB_CHECKSUM = 6;
        public static final byte NOTIF_KEY_UPDATE_STATUS = 7;
        public static final byte NOTIF_ACK_KEY_UPDATE_STATUS = 8;
        public static final byte NOTIF_SESSION_INIT = 9;
        public static final byte NOTIF_END_OF_UPDATE = 10;
        public static final byte NOTIF_RESPONSE = 11;
        public static final byte NOTIF_KEY_OPERATION_REQ_RCVD = 12;
        public static final byte NOTIF_KEY_DB_CHECKSUM = 13;
        public static final byte NOTIF_DEVICE_INFO = (byte) 0xff;
    }

    // 137
    public static class ONLINE_NOTIFY_RESPONSE_RESULT_CODE
    {
        public static final byte RESPONSE_CODE_REQUEST_SUCCESSFULLY_PROCESSED = 0;
        public static final byte RESPONSE_CODE_REQUEST_NOT_SUPPORTED = 1;
        public static final byte RESPONSE_CODE_MASSAGE_LENGTH_ERROR = 2;
        public static final byte RESPONSE_CODE_NO_MATCH_EXPECTED_KMC_ETCSIDEXP = 3;
        public static final byte RESPONSE_CODE_NO_MATCH_EXPECTED_MY_ETCSIDEXP = 4;
        public static final byte RESPONSE_CODE_UNSUPPORTED_IF_VERSION = 5;
        public static final byte RESPONSE_CODE_UNRECOVERABLE_KEY_DATABASE = 6;
        public static final byte RESPONSE_CODE_FAIL_REQUEST_PROCESSING = 7;
        public static final byte RESPONSE_CODE_CHECKSUM_MISMATCH = 8;
        public static final byte RESPONSE_CODE_SEQUENCE_NUMBER_MISMATCH = 9;
        public static final byte RESPONSE_CODE_TRANSACTION_NUMBER_MISMATCH = 10;
        public static final byte RESPONSE_CODE_FORMAT_ERROR = 11;
        public static final byte RESPONSE_CODE_OTHER_ERROR = (byte) 255;
    }

    // 137
    public static class RESPONSE_NOTIFICATION_RESULT_CODE
    {
        public static final byte NOTIFICATION_RESULT_REQUEST_SUCCESSFULLY_PROCESSED = 0;
        public static final byte NOTIFICATION_RESULT_UNKNOWN_KEY = 1;
        public static final byte NOTIFICATION_RESULT_MAX_NUM_OF_KEY_EXCEEDED = 2;
        public static final byte NOTIFICATION_RESULT_ALREADY_INSTALLED = 3;
        public static final byte NOTIFICATION_RESULT_KEY_CORRUPTED = 4;
        public static final byte NOTIFICATION_RESULT_RECIPIENT_ETCSID_MISMATCH = 5;
        public static final byte NOTIFICATION_RESULT_OTHER_ERROR = (byte) 255;
    }

    public static class REQUEST_KEY_OPERATION_REASON
    {
        public static final byte REASON_NEW_TRAIN = 0;
        public static final byte REASON_MODIFICATION_OF_AREA = 1;
        public static final byte REASON_REDUCED_PRIVILEGES = 2;
        public static final byte REASON_VALIDITY_EXPIRATION_NOTIFICATION = 3;
    }

    public static class NOTIF_KEY_UPDATE_STATUS_REASON
    {
        public static final byte REASON_INSTALLED = 1;
        public static final byte REASON_UPDATED = 2;
        public static final byte REASON_DELETED = 3;
    }


    public static class ONLINE_KEY_SIZE
    {
        public static final int HEADER_LENGTH_SIZE = 4;
        public static final int DEVICE_TIME_SIZE = 6;
        public static final int REQ_NUM_SIZE = 2;
        public static final int SNUM_SIZE = 4;
        public static final int KMAC_SIZE = 24;
        public static final int PEER_NUM_SIZE = 2;
        public static final int LENGTH_FILED_SIZE = 1;
        public static final int STATUS_FILED_SIZE = 1;
        public static final int IDENTIFIER_CNT_SIZE = 2;
        public static final int REASON_CODE_SIZE = 1;
        public static final int TEXT_LENGTH_SIZE = 2;
        public static final int APP_TIME_OUT_SIZE = 1;
        public static final int VERSION_SIZE = 1;
        public static final int INTERFACE_VERSION_SIZE = 1;
        public static final int RESPONSE_FILED_SIZE = 1;
        public static final int MAX_TIME_SIZE = 6;
        public static final int CHECKSUM_SIZE = 20;
        public static final int UNIT_SIZE = 1;
        public static final int TRANSACTION_SIZE = 4;
        public static final int SEQUENCE_SIZE = 2;
        public static final int MSG_TYPE_SIZE = 1;

        public static final int IDENTIFIER_STRUCT_SIZE = Common.COMMON_SIZE.ETCS_STRUCT_SIZE + SNUM_SIZE;
        public static final int VALIDITY_KEY_STRUCT_SIZE = IDENTIFIER_STRUCT_SIZE + Common.COMMON_SIZE.VALID_PERIOD_STRUCT_SIZE;
    }
}
