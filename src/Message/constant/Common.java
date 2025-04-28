package Message.constant;


public class Common
{
    /* 예외처리 문자열 정의 */
    public static class EXCEPTION_STRING
    {
        public static final String EXCEPTION_DESERIALIZE_FAIL = "The number of bytes remaining is too small to fill this field.";
        public static final String EXCEPTION_EXTRA_BYTE = "Input stream has extra bytes.";
        public static final String EXCEPTION_MESSAGE_VALUE_ERROR = "[IllegalArgument] Message value Error";
    }

    /* ETCS TYPE 정의 */
    public static class ETCS_TYPE
    {
        public static final byte RADIO_IN_FILL_UNIT = 0b00000000;
        public static final byte RBC = 0b00000001;
        public static final byte ENGINE = 0b00000010;
        public static final byte RESERVED_FOR_BALISE = 0b00000011;
        public static final byte RESERVED_FOR_FIELD_ELEMENT = 0b00000100;
        public static final byte KEY_MANAGEMENT_ENTITY = 0b00000101;
        public static final byte INTERLOCKING_RELATED_ENTITY = 0b00000110;
        public static final byte UNKNOWN = (byte)0b11111111;
    }


    /* SIZE 정의 */
    public static class COMMON_SIZE
    {
        public static final int ETCS_MESSAGE_TYPE_IDX = 0;

        public static final int EMPTY = 0 ;
        public static final int CBC_MAC_SIZE = 8;

        public static final int ETCS_ID_SIZE = 3;
        public static final int ETCS_ID_TYPE_SIZE = 1;
        public static final int ETCS_STRUCT_SIZE = ETCS_ID_SIZE + ETCS_ID_TYPE_SIZE;

        public static final int VALID_INSTANCE_SIZE = 4;
        public static final int VALID_PERIOD_STRUCT_SIZE = VALID_INSTANCE_SIZE +VALID_INSTANCE_SIZE;
    }
}

