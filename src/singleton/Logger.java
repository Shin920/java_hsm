package singleton;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * 로그 관리 싱글톤 클래스 * 블로킹 큐를 통해 순차적으로 로그 처리 진행
 * <p> GetInstance() 를 통해 인스턴스를 획득하고 Write(String message, int logType) 메서드를 통해 로그 작성
 * <p> 싱글톤 디자인 패턴으로 기본 생성자 호출은 허용하지 않음
 *
 *      <p>사용 할 쓰레드의 숫자 설정하는 값 만큼 멀티 쓰레딩
 *      <p>1. 파일 이름(LogTypeName) 에 파일이름 추가
 *      <p>2. 로그 타입 상수 순서에 맞춰 추가
 */
public class Logger
{
    /*
        사용 할 쓰레드의 숫자 설정하는 값 만큼 멀티 쓰레딩
        1. 파일 이름(LogTypeName) 에 파일이름 추가
        2. 로그 타입 상수 순서에 맞춰 추가
    */
    private static Logger instance;
    /* THREAD_COUNT 크기만큼 파일 이름 설정 */
    private static String LogDirectory;
    /* 파일 이름 정의 */
    private static final String[] LogTypeName = new String[]{
            "UncaughtException.log", /* 처리되지 않은 예외 발생 시 후킹하여 로깅 진행 */
            "codec.log",
            "DbHelper.log"
    };

    private static final int THREAD_COUNT = LogTypeName.length;
    /*
     *   로그 타입 상수 정의
     *   외부에서 Write 메서드를 이용할 떄 Type 부분에 해당하는 상수 삽입
     *  */
    public static final int LOG_TYPE_UNCAUGHT_EXCEPTION = 0;
    public static final int LOG_TYPE_CODEC = 1;
    public static final int LOG_TYPE_DATABASE_HELPER = 2;


    /* 로그 프로세서를 저장하는 배열 */
    private final LogProcessor[] logProcessors = new LogProcessor[THREAD_COUNT];

    /**
     *  Singleton 인스턴스를 반환하는 메서드
     *  */
    public static synchronized Logger GetInstance()
    {
        /*assert THREAD_COUNT == LogTypeName.length :  ("THREAD_COUNT Error ");*/
        if(THREAD_COUNT != LogTypeName.length)
        {
            System.err.println("[Logger] THREAD_COUNT value error ");
        }

        if (instance == null)
        {
            instance = new Logger();
        }

        return instance;
    }

    /* 생성자, 외부에서 접근하지 못하도록 private 으로 설정 */
    private Logger()
    {
        /* Thread.setDefaultUncaughtExceptionHandler(new UncaughtExceptionLogger()); */ /* 처리되지 않은 예외 발생 시 로깅 진행 */

        for (int i = 0; i < THREAD_COUNT; i++)
        {
            logProcessors[i] = new LogProcessor(LogTypeName[i]);
            logProcessors[i].setDaemon(true); /* 데몬 스레드로 설정 (따로 종료해주지 않아도 애플리케이션이 종료될 때 함께 종료) */
            logProcessors[i].start();
        }
    }

    private String AddTimeStampFromString(String Message)
    {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");
        LocalDateTime now = LocalDateTime.now();
        return String.format("%s : %s \n",now.format(formatter),Message);
    }

    /**
     * 로그 메시지를 큐에 추가하는 메서드
     * @param message 로그 메시지 내용
     * @param logType 로그 타입
     * @return 로깅 성공여부
     */
    public boolean Write(String message, int logType)
    {
        boolean bResult = !(logType < 0 || logType >= THREAD_COUNT); /* 타입 범위 체크 */

        CheckLogDirectory(); /* 디렉토리 체크 */

        message = AddTimeStampFromString(message);
        try
        {
            if(bResult)
            {
                logProcessors[logType].putLog(message);
            }
        }
        catch (Exception e)
        {
            Thread.currentThread().interrupt();
            bResult = false;
        }
        finally
        {
            return bResult;
        }
    }

    /**
     *  로그를 작성할 디렉토리가 있는 지 체크하고 없다면 생성
     *  */
    private static void CheckLogDirectory()
    {
        String strPath = System.getProperty("user.dir");
        String strDirectoryPath = strPath + "/log" ;
        try /* 작업 위치에 로그 디렉토리 생성 */
        {
            Path path;

            path =Paths.get(strDirectoryPath);
            if( !Files.isDirectory(path) )  /* 로그 폴더가 존재하지 않는다면 디렉토리 생성 */
            {
                Files.createDirectory(path);
            }

            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("/yyMM");
            LocalDateTime now = LocalDateTime.now();
            path =Paths.get( strDirectoryPath + String.format("%s",now.format(formatter)) );
            if( !Files.isDirectory(path) )  /* 로그 폴더가 존재하지 않는다면 디렉토리 생성 */
            {
                Files.createDirectory(path);
            }

            LogDirectory = path.toString() + "/";
        }
        catch (IOException e)
        {
            if( !(e instanceof FileAlreadyExistsException) )
            {
                e.printStackTrace();
            }
        }
    }

    /**
     * 로그를 처리하는 내부 클래스
     */
    private static class LogProcessor extends Thread
    {
        private final int MAX_LOG_CNT = 100; // 큐의 최대 크기
        private final String LOG_FILE_NAME;
        private final BlockingQueue<String> logQueue = new LinkedBlockingQueue<>(MAX_LOG_CNT);

        public LogProcessor(String fileName)
        {
            this.LOG_FILE_NAME = fileName;
        }

        /* 로그 메시지를 큐에 추가하는 메서드 */
        public void putLog(String message) throws InterruptedException
        {
            logQueue.put(message);
        }

        @Override
        public void run()
        {
            try
            {
                while (true)
                {
                    String message = logQueue.take();
                    ProcessLog(message);
                }
            }
            catch (InterruptedException e)
            {
                Thread.currentThread().interrupt();
            }
        }

        /* 로그 메시지를 실제로 처리하는 메서드 */
        private void ProcessLog(String logMessage)
        {
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd_");
            LocalDateTime now = LocalDateTime.now();
            /* save log file */
            try (FileWriter logWriter = new FileWriter(LogDirectory + now.format(formatter) + this.LOG_FILE_NAME, true) )
            {
                logWriter.write(logMessage);
            }
            catch (IOException e)
            {
                e.printStackTrace();
            }
        }
    }

    /**
     * 쓰레드 프로세스 중 처리되지 않은 예외가 발생하면 여기서 예외를 후킹하여 대신 처리하고 예외가 발생한 쓰레드는 종료됨
     * <p>* 이 쓰레드가 호출됐다면 로그를 확인하고 try catch 블록으로 묶어서 처리 해줘야 함
     */
    public static class UncaughtExceptionLogger implements Thread.UncaughtExceptionHandler
    {
        @Override
        public void uncaughtException(Thread t, Throwable e)
        {
            String strLogMsg = String.format( "uncaughtException [ %s ] \n %s ", t.getName(), ExceptionStackTraceToString(e) );
            if( Write(strLogMsg) ) /* 파일에 로깅 진행 */
            {
                System.err.println(strLogMsg); /* 파일 기록이 완료됐다면 콘솔창에 에러 메시지 출력 */
            }
        }

        /**
         * 처리되지 않은 예외를 파일로 기록
         * @param strLogMsg 로그 파일에 기록할 메시지
         * @return 기록 성공여부
         */
        private boolean Write(String strLogMsg)
        {
            Logger logger = Logger.GetInstance(); /* 로거는 사용할때만 인스턴스를 획득 */
            return logger.Write(strLogMsg, LOG_TYPE_UNCAUGHT_EXCEPTION);
        }

        /**
         * 던져진 예외 스택 트레이스를 문자열로 추출
         * @param throwable 발생한 예외
         * @return 추출한 문자열
         */
        private String ExceptionStackTraceToString(Throwable throwable)
        {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            throwable.printStackTrace(pw);
            return sw.toString();
        }
    }
}