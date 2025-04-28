package config;

public class AppConfig {

    public static class DB_CONFIG
    {
        /* 공통 */
        public static int ERROR = -1;
        public static int NO_ERROR = 0;

        /* 쿼리 타입 */
        public static final int USABLE_QUERY_CNT = 4;
        public static final int QUERY_TYPE_NOT_SELECTED = -1;
        public static final int QUERY_SELECT = 0;
        public static final int QUERY_UPDATE = QUERY_SELECT + 1;
        public static final int QUERY_INSERT = QUERY_UPDATE + 1;
        public static final int QUERY_DELETE = QUERY_INSERT + 1 ;

        /* DATABASE 연결 정보 */
        private static final String JDBC_INFORMATION = "jdbc:mariadb://";
        private static final String KMC_IP = "192.168.75.110";
        private static final String KMC_PORT = "3306";
        private static final String KMC_DBNAME = "kmc";
        public static final String CONNECTION_INFORMATION = JDBC_INFORMATION + KMC_IP + ":" + KMC_PORT + "/" + KMC_DBNAME;
        public static final String DRIVER_NAME = "org.mariadb.jdbc.Driver";
        public static final String KMC_ID = "kmc";
        public static final String KMC_PASSWORD = "kmc1234";

        /* 타임아웃 */
        public static final long MAX_TIMEOUT = 60;
        public static final long QUERY_TIMEOUT = 3;
        public static final int TIMEOUT_CHECK_INTERVAL = 100;
        public static final int TIMEOUT_SEC_SETTING_OF_INTERVAL = 1000 / TIMEOUT_CHECK_INTERVAL;

    }
}
