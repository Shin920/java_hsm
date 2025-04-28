import com.nb.kms.hsm.EventMsg;
import com.nb.kms.hsm.HsmMsg;
import com.nb.kms.hsm.HsmStatus;
import com.nb.kms.hsm.EventMsg.*;

import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

public class HsmMsgClient {

    public static void main(String[] args) {
        String serverAddress = "192.168.75.110"; // 서버 IP
        int serverPort = 5000; // 서버 포트
        String clientAddress = "192.168.75.88"; // 클라이언트 IP
        int clientPort = 5001; // 클라이언트가 결과를 받을 포트

        //암복호화 테스트용 원본데이터
        byte[] plainData = {0x12, 0x03, 0x3C, 0x56, 0x4F, 0x6B, 0x1A, 0x32, 0x12, 0x03, 0x3C, 0x56, 0x4F, 0x6B, 0x1A, 0x32, 0x12, 0x03, 0x3C, 0x56, 0x4F, 0x6B, 0x1A, 0x32};
        byte[] encryptedData = {0x71, 0x02, 0x64, 0x66, (byte) 0xD5, 0x12, (byte) 0x9F, 0x74, (byte) 0x8D, (byte) 0xC8, 0x70, 0x47, 0x5E, 0x29, 0x03, (byte) 0xCB, 0x00, (byte) 0xAC, (byte) 0xF6, 0x69, (byte) 0xB5, (byte) 0x82, 0x70, 0x32};


        HsmMsg.hsmMsgHeader header = new HsmMsg.hsmMsgHeader(EventMsg.HSM_HEADER.HEADER_TYPE_HSM, clientAddress, clientPort);
        // 암복호화 테스트
        //HsmMsg msg = new HsmMsg(header, HSM_MSG_TYPE.GET_KEY, HSM_KEY_TYPE.DES3_TYPE, 3459, 7773310, KEY_GEN_TYPE.ktransKey1);
        //HsmMsg msg = new HsmMsg(header, HSM_MSG_TYPE.GET_KCV, HSM_KEY_TYPE.DES3_TYPE, 1998, 770920, KEY_GEN_TYPE.ktransKey1);
        //HsmMsg msg = new HsmMsg(header, HSM_MSG_TYPE.GET_STATUS);
        // 키 복사용
        //HsmMsg msg = new HsmMsg(header, HSM_MSG_TYPE.COPY_KEY, HSM_KEY_TYPE.DES3_TYPE, 920, 7774685, KEY_GEN_TYPE.ktransKey1, 1998, 770920);
        // 키 주입 테스트
        //HsmMsg msg = new HsmMsg(header, HSM_MSG_TYPE.INJECT_KEY, HSM_KEY_TYPE.DES3_TYPE, 3459, 7773310, KEY_GEN_TYPE.ktransKey1, plainData);
        // 주입 된 키 확인
        HsmMsg msg = new HsmMsg(header, HSM_MSG_TYPE.GET_KEY, HSM_KEY_TYPE.DES3_TYPE, 3459, 7773310, KEY_GEN_TYPE.ktransKey1);



        // 클라이언트에서 서버로 메시지를 전송하는 스레드
        try (Socket socket = new Socket()) {
            System.out.println("Attempting to connect to server...");
            socket.connect(new InetSocketAddress(serverAddress, serverPort), 5000);
            System.out.println("Connected to server: " + serverAddress);

            try (ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {
                System.out.println("Sending HsmMsg...");
                oos.writeObject(msg);
                oos.flush();
                System.out.println("HsmMsg sent successfully.");
            }
        } catch (IOException e) {
            System.err.println("Error during communication: " + e.getMessage());
            e.printStackTrace();
            return;  // 통신 오류 시 더 이상 진행하지 않음
        }

        // 응답을 받기 위한 데몬 스레드 시작
        Thread responseThread = new Thread(() -> {
            try (ServerSocket responseServerSocket = new ServerSocket(clientPort)) {
                System.out.println("Waiting for response from server...");

                while (true) {  // 계속해서 응답을 기다림
                    try (Socket responseSocket = responseServerSocket.accept();
                         ObjectInputStream ois = new ObjectInputStream(responseSocket.getInputStream())) {

                        Object response = null;

                        try {
                            response = ois.readObject();  // 객체 읽기 시도
                        } catch (EOFException eofException) {
                            // 스트림 끝에 도달했을 때 발생하는 예외를 처리
                            System.err.println("Reached end of stream unexpectedly: " + eofException.getMessage());
                            continue;  // 그냥 다음 루프로 넘어가도록 함
                        }

                        if (response == null) {
                            System.err.println("Received null response from server.");
                            continue;  // Null인 경우 메시지를 처리하지 않고 다음 반복으로 넘어감
                        }

                        System.out.println("Received response from server.");

                        if (response instanceof String) {
                            System.out.println("Response from server: " + response);
                        } else if (response instanceof byte[]) {
                            System.out.println("Response from server (byte[]): " + bytesToHex((byte[]) response));
                        } else if (response instanceof HsmStatus) {
                            // HsmStatus 객체 처리
                            HsmStatus hsmStatus = (HsmStatus) response;
                            System.out.println("HSM State: " + hsmStatus.getHsmState());
                            System.out.println("Network Status: " + hsmStatus.getNetworkStatus());
                        }
                    } catch (IOException | ClassNotFoundException e) {
                        System.err.println("Error during receiving response: " + e.getMessage());
                        e.printStackTrace();
                    }
                }

            } catch (IOException e) {
                System.err.println("Error setting up response server socket: " + e.getMessage());
                e.printStackTrace();
            }
        });

        responseThread.setDaemon(true);  // 스레드를 데몬 스레드로 설정
        responseThread.start();

        // 메인 스레드가 종료될 때까지 대기 (예: 사용자 입력 대기)
        try {
            System.out.println("Press Enter to exit...");
            System.in.read();
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("Client is shutting down...");
    }

    // 바이트 배열을 16진수 문자열로 변환하는 헬퍼 메서드
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b)); // 각 바이트를 2자리 16진수로 변환
        }
        return sb.toString();
    }
}