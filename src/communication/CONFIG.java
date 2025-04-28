package communication;

public class CONFIG
{
    public static class HSM_PACKET
    {
        public static final byte HEADER_TYPE_HSM = 0x00; /* HSM 패킷 */
        public static final byte HEADER_TYPE_WEB_APP = 0x01; /* WEB 패킷 */
        public static final byte HEADER_TYPE_DIST_APP = 0x02; /* DIST 패킷 */

        /* TODO : 이벤트 타입 정의 */
    }

    public static class TCP_CONFIG
    {
        /* 서버 구성 정보  */
        public static final String SERVER_IP = "127.0.0.1";
        public static final int SERVER_PORT = 15000;
        /* ******************************************************************************/
    }
}

