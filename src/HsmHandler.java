import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;

import Threads.*;
import com.nb.kms.hsm.EventMsg.*;
import com.nb.kms.hsm.HsmMsg;
import com.nb.kms.hsm.Logger;
import safenet.jcprov.*;
import safenet.jcprov.constants.CKF;
import safenet.jcprov.constants.CKU;

public class HsmHandler {
    private static BlockingQueue<HsmMsg> taskQueue;

    private static HsmHandler instance;
    private CK_SESSION_HANDLE session = null;

    private final AtomicInteger state = new AtomicInteger(0); // 0: disconnected, 1: connected


    static {
        taskQueue = new LinkedBlockingQueue<>();
    }

    public static synchronized HsmHandler getInstance() {
        if (instance == null) {
            instance = new HsmHandler();
        }
        return instance;
    }

    public static void main(String[] args) {
        HsmHandler handler = HsmHandler.getInstance();
        // 세션 초기화
        //hsmService.initializeSession(HSM_INFO.SLOT_ID, HSM_INFO.PASSWORD);
        handler.initializeSession(HSM_INFO.SLOT_ID, HSM_INFO.PASSWORD);

        // HSMWorkerThread에 세션 핸들을 넘겨줌
        new Thread(new EventReceiverThread(taskQueue)).start();
        new Thread(new HSMWorkerThread(taskQueue, handler.getSessionHandle())).start();

        // 작업을 추가하는 예제
        // TCP 통신 확인을 위한 주석처리
        /*hsmMsgHeader header = new hsmMsgHeader(HSM_HEADER.HEADER_TYPE_HSM, "localhost", 5001);
        addTask(new HsmMsg(header, HSM_MSG_TYPE.GENERATE_KEY, HSM_KEY_TYPE.DES_TYPE, "brandNewKey"));
        addTask(new HsmMsg(header, HSM_MSG_TYPE.GENERATE_KEY, HSM_KEY_TYPE.DES3_TYPE, "DES3KEY"));*/


        // 세션 종료를 특정 조건에 맞춰 호출 (프로그램 종료)
        Runtime.getRuntime().addShutdownHook(new Thread(() -> handler.closeSession()));

    }

    public synchronized void initializeSession(long slotId, String password) {
        if (state.compareAndSet(0, 1)) {
            try {
                session = new CK_SESSION_HANDLE();
                CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));
                CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, session);

                if (!password.isEmpty()) {
                    CryptokiEx.C_Login(session, CKU.USER, password.getBytes(), password.length());
                }

                Logger.log("INFO", "Session initialized for slot " + slotId + " password " + password);
            } catch (CKR_Exception e) {
                Logger.error("Error initializing session", e);
                state.set(0); // 초기화 실패시 상태를 복원
            }
        } else {
            Logger.log("INFO", "Session is already initialized");
        }
    }

    public synchronized void closeSession() {
        if (state.compareAndSet(1, 0)) {
            if (session != null) {
                try {
                    Cryptoki.C_Logout(session);
                    Cryptoki.C_CloseSession(session);
                    Cryptoki.C_Finalize(null);
                } catch (CKR_Exception ex) {
                    Logger.error("Error closing session", ex);
                } finally {
                    session = null;
                }
            }
            Logger.log("INFO", "Session closed");
        }
    }

    // 작업을 큐에 추가하는 메서드
    public static void addTask(HsmMsg task) {
        taskQueue.add(task);
    }
    public CK_SESSION_HANDLE getSessionHandle() {
        return session;
    }
    public void setSessionHandle(CK_SESSION_HANDLE session) { this.session = session; }
}