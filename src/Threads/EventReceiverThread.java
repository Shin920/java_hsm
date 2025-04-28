package Threads;

import com.nb.kms.hsm.HsmMsg;
import com.nb.kms.hsm.Logger;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.BlockingQueue;

public record EventReceiverThread(BlockingQueue<HsmMsg> taskQueue) implements Runnable {

    @Override
    public void run() {
        try (ServerSocket serverSocket = new ServerSocket(5000)) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                new Thread(() -> handleClient(clientSocket)).start(); // 클라이언트 연결을 별도 스레드에서 처리
            }
        } catch (IOException e) {
            Logger.error("Server socket error", e);
        }
    }

    private void handleClient(Socket clientSocket) {
        try (ObjectInputStream ois = new ObjectInputStream(clientSocket.getInputStream())) {
            Object receivedObject = ois.readObject();

            if (receivedObject instanceof HsmMsg) {
                HsmMsg task = (HsmMsg) receivedObject;

                if (isValidHsmMsg(task)) {
                    taskQueue.put(task);
                } else {
                    Logger.error("Received HsmMsg has invalid fields: " + task);
                }
            } else {
                Logger.error("Received object is not of type HsmMsg: " + receivedObject.getClass().getName());
            }
        } catch (ClassNotFoundException | InterruptedException e) {
            Logger.error("Error processing client request", e);
            Thread.currentThread().interrupt();
        } catch (IOException e) {
            Logger.error("I/O error occurred", e);
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                Logger.error("Failed to close client socket", e);
            }
        }
    }

    // 유효성 검사 메서드
    private boolean isValidHsmMsg(HsmMsg task) {
        // Header부분 null이 아닌지, Operation 값이 유효한지 확인 (다른 조건 OR 제외됨)
        if (task.getOperation() < 0 || task.getHeader() == null) {
            return false;
        }
        // 추가적인 유효성 검사 로직 추가 가능
        return true;
    }

    @Override
    public BlockingQueue<HsmMsg> taskQueue() {
        return taskQueue;
    }
}