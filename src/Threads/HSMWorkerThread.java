package Threads;

import com.nb.kms.hsm.*;
import safenet.jcprov.CK_SESSION_HANDLE;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.concurrent.BlockingQueue;
import com.nb.kms.hsm.EventMsg.*;

public class HSMWorkerThread implements Runnable {
    private final BlockingQueue<HsmMsg> taskQueue;
    private CK_SESSION_HANDLE session = null;

    public HSMWorkerThread(BlockingQueue<HsmMsg> taskQueue, CK_SESSION_HANDLE session) {
        this.taskQueue = taskQueue;
        this.session = session;
    }

    @Override
    public void run() {
        while (true) {
            try {
                HsmMsg task = taskQueue.take(); // 작업 큐에서 하나의 작업을 가져옴
                Object result = processTask(task); // 작업을 처리함
                Logger.log("INFO", "Task processed: " + result.toString());

                // 결과를 TCP로 전송 -> processTask로


            } catch (InterruptedException e) {
                Logger.error("Worker thread interrupted", e);
                Thread.currentThread().interrupt();
            }
        }
    }

    private Object processTask(HsmMsg task) {
        HsmService hsmService = HsmService.getInstance();
        hsmService.setSessionHandle(session);

        try {
            // task.getOperation()에 따른 기본 분기 처리
            switch (task.getOperation()) {
                case HSM_MSG_TYPE.GENERATE_KEY -> {

                    hsmService.generateKey(task.getKeyType(), task.getKeyGenType(), task.getSerialNum(), task.getEtcsId());
                    byte[] kcv = hsmService.calculateKCV(task.getKeyType(), task.getKeyGenType(), task.getSerialNum(), task.getEtcsId());
                    sendResult(task.getHeader(), kcv);
                    return "Key generated";
                }
                case HSM_MSG_TYPE.COPY_KEY -> {

                    // 키 복사 수행
                    hsmService.copyKey(task.getKeyGenType(), task.getSerialNum(), task.getEtcsId(), task.getNewSerialNum(), task.getNewEtcsId(), HSM_INFO.PASSWORD);

                    // 결과 메시지 전송
                    sendResult(task.getHeader(), "Key copied from " + task.getSerialNum() + " to " + task.getNewSerialNum());
                    return "Key copied";
                }
                case HSM_MSG_TYPE.CALCULATE_CBC -> {
                    String keyLabel = hsmService.makeLabel(task.getKeyGenType(), task.getSerialNum(), task.getEtcsId());

                    // 원본 키의 KCV 계산
                    byte[] calculatedKCV = hsmService.calculateKCV(task.getKeyType(), task.getKeyGenType(), task.getSerialNum(), task.getEtcsId());
                    if (calculatedKCV == null) {
                        Logger.log("ERROR", "Failed to calculate KCV for key label: " + keyLabel);
                        sendResult(task.getHeader(), "Failed to calculate KCV.");
                        return "Failed to calculate KCV.";
                    }

                    // DB에서 KCV 가져오기
                    HsmDBService dbService = HsmDBService.getInstance();
                    String dbKCV = dbService.getKCV(keyLabel);
                    if (dbKCV == null) {
                        Logger.log("ERROR", "Failed to retrieve KCV from DB for key label: " + keyLabel);
                        sendResult(task.getHeader(), "Failed to retrieve KCV from DB.");
                        return "Failed to retrieve KCV from DB.";
                    }

                    // KCV 비교
                    if (hsmService.bytesToHex(calculatedKCV).equals(dbKCV)) {
                        // KCV가 일치하는 경우에만 CBC-MAC 계산
                        byte[] cbcMac = hsmService.calculateCBCMAC(task.getKeyGenType(), task.getSerialNum(), task.getEtcsId(), task.getData());
                        sendResult(task.getHeader(), cbcMac);
                        return "CBC-MAC Calculated";
                    } else {
                        Logger.log("ERROR", "KCV mismatch for key label: " + keyLabel);
                        sendResult(task.getHeader(), "KCV mismatch.");
                        return "KCV mismatch.";
                    }
                }
                case HSM_MSG_TYPE.DELETE_KEY -> {

                    hsmService.deleteKey(task.getKeyType(), task.getKeyGenType(), task.getSerialNum(), task.getEtcsId());
                    sendResult(task.getHeader(), "Key deleted: " + task.getKeyGenType());
                    return "Key deleted: " + task.getKeyGenType();
                }

                case HSM_MSG_TYPE.ENCRYPT_KEY -> {

                    // 데이터 암호화 수행
                    byte[] encryptedData = hsmService.encryptDataWithKey(task.getKeyGenType(), task.getSerialNum(), task.getEtcsId(), task.getData());
                    if (encryptedData == null) {
                        Logger.log("ERROR", "Failed to encrypt data with key label: " + task.getKeyGenType());
                        sendResult(task.getHeader(), "Failed to encrypt data.");
                        return "Failed to encrypt data.";
                    }

                    // 결과 전송
                    sendResult(task.getHeader(), encryptedData);
                    return "Data encrypted successfully.";
                }
                case HSM_MSG_TYPE.DECRYPT_KEY -> {

                    // 데이터 복호화 수행
                    byte[] decryptedData = hsmService.decryptDataWithKey(task.getKeyGenType(), task.getSerialNum(), task.getEtcsId(), task.getData());
                    if (decryptedData == null) {
                        Logger.log("ERROR", "Failed to decrypt data with key label: " + task.getKeyGenType());
                        sendResult(task.getHeader(), "Failed to decrypt data.");
                        return "Failed to decrypt data.";
                    }

                    // 결과 전송
                    sendResult(task.getHeader(), decryptedData);
                    return "Data decrypted successfully.";
                }
                case HSM_MSG_TYPE.GET_KCV -> {

                    byte[] kcv = hsmService.calculateKCV(task.getKeyType(), task.getKeyGenType(), task.getSerialNum(), task.getEtcsId());
                    sendResult(task.getHeader(), kcv);
                    return kcv != null ? kcv : "Failed to calculate KCV.";
                }
                case HSM_MSG_TYPE.GET_KEY -> {

                    byte[] plainTextKey = hsmService.getPlainTextKey(task.getKeyType(), task.getKeyGenType(), task.getSerialNum(), task.getEtcsId());
                    sendResult(task.getHeader(), plainTextKey);
                    return plainTextKey != null ? plainTextKey : "Failed to retrieve plaintext key.";
                }
                case HSM_MSG_TYPE.GET_STATUS -> {
                    // HSM 상태와 네트워크 상태 확인
                    HsmStatus status = hsmService.getHsmStatusAndNetworkState(task.getHeader().getAddress());

                    // 결과를 외부 앱에 전송
                    sendResult(task.getHeader(), status);
                    return status.toString(); // 객체의 상태를 로그에 남기기 위해 문자열로 반환
                }
                case HSM_MSG_TYPE.INJECT_KEY -> {
                    hsmService.injectPrivateKey(task.getKeyType(), task.getKeyGenType(), task.getSerialNum(), task.getEtcsId(), task.getData());
                    byte[] kcv = hsmService.calculateKCV(task.getKeyType(), task.getKeyGenType(), task.getSerialNum(), task.getEtcsId());
                    sendResult(task.getHeader(), kcv);
                    return kcv != null ? kcv : "Failed to calculate KCV.";
                }
                default -> Logger.error("Unsupported operation type: " + task.getOperation());
            }


        } catch (Exception ex) {
            Logger.error("Error processing task", ex);
            return "Error processing task: " + ex.getMessage();
        }
        return null;
    }

    // 객체를 전송하는 sendResult 메서드
    private void sendResult(HsmMsg.hsmMsgHeader header, Object message) {

        if (message == null) {
            Logger.error("Attempted to send a null message to " + header.getAddress() + ":" + header.getPort());
            return;
        }

        try (Socket socket = new Socket(header.getAddress(), header.getPort());
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {
            oos.writeObject(message);
            oos.flush();
        } catch (IOException e) {
            Logger.error("Failed to send message via TCP", e);
        }
    }

    public String bytesToDecimalString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(Byte.toUnsignedInt(b));  // 각 바이트를 부호 없는 10진수로 변환
        }
        return sb.toString();
    }
}