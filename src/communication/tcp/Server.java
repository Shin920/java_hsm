package communication.tcp;

import communication.CONFIG.*;
import communication.packet.HsmPacket;

import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.Arrays;


/**
 * TcpServer TCP 서버 쓰레드는 싱글톤 패턴으로
 * {@link #GetInstance()} 를 통해 인스턴스를 획득하여 사용
 */
public class Server extends Thread
{

    private static Server instance;
    private ServerSocket serverSocket;

    private Server()
    {
        this.setDaemon(true); /* 자신을 데몬 쓰레드로 설정 * 데몬 쓰레드 : 메인 프로세스가 종료되면 같이 종료됨 */
    }


    public static synchronized Server GetInstance()
    {
        if (instance == null)
        {
            instance = new Server();
        }
        return instance;
    }

    private String GetServerIP()
    {
        return TCP_CONFIG.SERVER_IP;
    }

    private int GetServerPort()
    {
        return TCP_CONFIG.SERVER_PORT;
    }

    @Override
    public void run()
    {
        try
        {
            serverSocket = new ServerSocket(GetServerPort(), 0, InetAddress.getByName(GetServerIP()));
            System.out.println("Server started on " + GetServerIP() + ":" + GetServerPort());

            while (true)
            {
                // 클라이언트 연결을 수락
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected: " + clientSocket.getInetAddress());

                /* 클라이언트 요청을 처리하기 위해 새로운 스레드 생성 */
                new ClientHandler(clientSocket).start(); /*  */
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        finally
        {
            if (serverSocket != null && !serverSocket.isClosed())
            {
                try
                {
                    serverSocket.close();
                }
                catch (Exception e)
                {
                    e.printStackTrace();
                }
            }
        }
    }

    /* 클라이언트 핸들링 클래스 */
    private static class ClientHandler extends Thread
    {
        private  HsmPacket hsmPacketClass;
        private final Socket clientSocket;
        private final byte[] buffer = new byte[1024]; /* 최대 버퍼 크기 : 1KB  */

        public ClientHandler(Socket clientSocket)
        {
            this.clientSocket = clientSocket;
        }

        private void PrintByteArray(byte[] bArray)
        {
            System.out.printf("SIZE [%d] : ", bArray.length);
            for(byte b : bArray)
            {
                System.out.printf("%02X ",b);
            }

            System.out.println();
        }

        @Override
        public void run() {
            try {
                // 클라이언트와의 입출력 스트림 생성
                InputStream in = clientSocket.getInputStream();
                OutputStream out = clientSocket.getOutputStream();

                // 클라이언트 메시지 처리
                int bytesRead;
                while ((bytesRead = in.read(this.buffer)) != -1) {
                    byte[] bReceivedBuffer = Arrays.copyOfRange(this.buffer, 0, bytesRead); /* 받은 크기만큼 버퍼를 자름 */
                    PrintByteArray(bReceivedBuffer); /* 받은 바이트 버퍼 출력 */

                    /* TODO : 받은 데이터 처리 ( actualData ) *
                        1. 어디서 받았는지 분기 처리
                        2. 리시브,이벤트 타입 처리
                        3. 바디데이터 처리
                        4. 바디데이터와 이벤트 타입을 통해 Send Data 생성
                    */
                    /* 1. 받은 데이터 디코딩  */
                    this.hsmPacketClass = new HsmPacket();
                    if( this.hsmPacketClass.DecodeMessage(bReceivedBuffer) )
                    {
                        /* 2. 리시브,이벤트 타입 처리 */
                        if( !hsmPacketClass.isCheckHeader() ) /* 헤더 타입과 이벤트가 정상인지 체크 */
                        {
                            continue; /* 해더 체크 실패 시 다시 수신대기 */
                        }

                        /* 3. 바디데이터 처리  */
                        switch (hsmPacketClass.getHeaderType()) /* TODO : 들어온 요청 데이터를 체크하고 알맞은 HSM API 호출하고 값 반환받음 */
                        {
                            case HSM_PACKET.HEADER_TYPE_DIST_APP ->
                            {
                                /* TODO : 이벤트 타입 체크 후 데이터 처리 */
                            }
                            case HSM_PACKET.HEADER_TYPE_WEB_APP ->
                            {
                                /* WEB APP 에서 온 데이터 */
                                /* TODO : 이벤트 타입 체크 후 데이터 처리 */
                            }
                            default ->
                            {
                                System.out.println("알 수 없는 패킷 타입");
                            }
                        }
                    }
                    byte EVENT_TYPE = 0x00;
                    byte[] BODY_DATE = new byte[]{(byte)0x00,(byte)0x01,(byte)0x02};
                    /* 4. 리턴 데이터 생성 (현재 더미 데이터) */
                    HsmPacket hsmPacket = new HsmPacket(HSM_PACKET.HEADER_TYPE_HSM,EVENT_TYPE,BODY_DATE);


                    /*
                    * TODO : 받은 데이터 처리를 통해 가공된 데이터를 다시 프로토콜에 맞춰 바이트배열로 만들고 재전송
                    *   * 현재 받은 데이터를 그대로 클라이언트로 전송
                    *  */
                    out.write(hsmPacket.EncodeObject(), 0, hsmPacket.GetSize());
                }
            }
            catch (Exception e)
            {
                if(e instanceof SocketException) /* 상태가 연결을 끊었을 시 예외처리 */
                {
                    System.out.println("Client Disconnected");
                }
                else
                {
                    e.printStackTrace(); /* SocketException 외의 익셉션 발생 시 스택 트레이스 출력 */
                }
            }
            finally
            {
                try
                {
                    if (clientSocket != null && !clientSocket.isClosed())
                    {
                        clientSocket.close();
                    }
                }
                catch (Exception e)
                {
                    e.printStackTrace();
                }
            }
        }
    }

    public static void main(String[] args)
    {
        Server server = Server.GetInstance();
        server.start();

        while(true)
        {
            try
            {
                sleep(100);
            }
            catch (InterruptedException e)
            {
                throw new RuntimeException(e);
            }
        }
    }
}
