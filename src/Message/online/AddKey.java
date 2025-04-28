package Message.online;


import Message.CodecUtil;
import Message.constant.Common.*;
import Message.constant.Online.*;
import Message.online.sub.OnlineKeyStruct;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.LinkedList;
import java.util.Queue;

public class AddKey extends CodecUtil
{
    private byte[] reqNum = new byte[ONLINE_KEY_SIZE.REQ_NUM_SIZE];
    private OnlineKeyStruct[] KeyStruct = null;

    public AddKey() {}

    /**
     * 기본 생성자
     * @param reqNum The number of K-STRUCT structures that follow. ( 1..100 )
     * @param KeyStruct k_struct
     */
    public AddKey(byte[] reqNum, OnlineKeyStruct[] KeyStruct)
    {
        SetReqNum(reqNum);
        SetKeyStruct(KeyStruct);
    }

    /**
     * 바이트 배열을 통해 구조체 초기화
     * @param bAddKeyMessage 메시지 패킷
     */
    public AddKey(byte[] bAddKeyMessage) throws IllegalArgumentException
    {
        if(DecodeMessage(bAddKeyMessage) != ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_REQUEST_SUCCESSFULLY_PROCESSED)
        {
            throw new IllegalArgumentException(EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
        }
    }
    /**
     * 바이트 배열을 통해 구조체 초기화
     * @param bAddKeyMessage 메시지 패킷
     */
    public int DecodeMessage(byte[] bAddKeyMessage)
    {
        try
        {
            return DeserializeFromBytes(bAddKeyMessage);
        }
        catch (Exception e)
        {
            super.IsExceptionPrintingAndWriteLog(e);
            return ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_OTHER_ERROR;
        }
    }

    /**
     * @return 클래스 필드 인스턴스들의 값을 바이트 배열로 직렬화하여 반환
     */
    public byte[] EncodeObject() throws IOException
    {
        try
        {
            byte[] bStructBuffer = new byte[COMMON_SIZE.EMPTY];
            for(OnlineKeyStruct object : this.KeyStruct){
                bStructBuffer = super.AddPacket(bStructBuffer,object.EncodeObject());
            }

            return super.SerializeMultipleByteArrays(
                    this.reqNum,
                    bStructBuffer
            );
        }
        catch (IOException e)
        {
            super.IsExceptionPrintingAndWriteLog(e);
            return super.MakeErrorPacket(GetSize());
        }
    }

    private int DeserializeFromBytes(byte[] byteArrayInputStream) throws Exception
    {
        if (byteArrayInputStream == null || byteArrayInputStream.length == COMMON_SIZE.EMPTY)
        {
            super.IsExceptionPrintingAndWriteLog(new IllegalArgumentException("Input stream is null or empty"));
            return ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_FORMAT_ERROR;
        }

        try (ByteArrayInputStream bais = new ByteArrayInputStream(byteArrayInputStream);
             DataInputStream dis = new DataInputStream(bais))
        {
            try  /* EOF Check */
            {
                dis.readFully(this.reqNum);
                int nReqNum = super.ConvertByteArrayToInt(this.reqNum);
                if(!(nReqNum >= 1 && nReqNum <= 100))
                {
                    IsExceptionPrintingAndWriteLog(new IllegalArgumentException("nReqNum value Error"));
                    return ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_FORMAT_ERROR;
                }

                { /* Insert K-Struct */
                    Queue<byte[]> k_structPacket = new LinkedList<>();
                    do {
                        byte bLength = dis.readByte();
                        byte[] bIdentifier = new byte[ONLINE_KEY_SIZE.IDENTIFIER_STRUCT_SIZE];
                        dis.readFully(bIdentifier);
                        byte[] bKmcId = new byte[COMMON_SIZE.ETCS_STRUCT_SIZE];
                        dis.readFully(bKmcId);
                        byte[] bEnc = new byte[ONLINE_KEY_SIZE.KMAC_SIZE];
                        dis.readFully(bEnc);
                        byte[] bPeerNum = new byte[ONLINE_KEY_SIZE.PEER_NUM_SIZE];
                        dis.readFully(bPeerNum);
                        int nPeerIdLength = ConvertByteArrayToInt(bPeerNum) * COMMON_SIZE.ETCS_STRUCT_SIZE;
                        byte[] nPeerId = new byte[nPeerIdLength];
                        dis.readFully(nPeerId);
                        byte[] bValidPeriod = new byte[COMMON_SIZE.VALID_PERIOD_STRUCT_SIZE];
                        dis.readFully(bValidPeriod);

                        /* 설정한 값들을 하나의 바이트 배열로 변환*/
                        k_structPacket.add(
                                super.SerializeMultipleByteArrays(
                                        new byte[]{bLength},
                                        bIdentifier,
                                        bKmcId,
                                        bEnc,
                                        bPeerNum,
                                        nPeerId,
                                        bValidPeriod
                                ));
                        /* CRC 사이즈 또는 그 이하로 남는다면 남은 K_STRUCT 가 없음  */
                        if (dis.available() <= COMMON_SIZE.CBC_MAC_SIZE) {
                            break;
                        }
                    } while (true);
                    int nPacketSize = k_structPacket.size();
                    this.KeyStruct = new OnlineKeyStruct[nPacketSize];
                    for (int idx = 0; idx < nPacketSize; idx++)
                    {
                        this.KeyStruct[idx] = new OnlineKeyStruct(k_structPacket.poll());
                    }
                }

                /* 스트림에 남은 바이트가 있는지 확인 */
                if (dis.available() > COMMON_SIZE.EMPTY)
                {
                    IsExceptionPrintingAndWriteLog(new IllegalArgumentException(EXCEPTION_STRING.EXCEPTION_EXTRA_BYTE));
                    return ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_FORMAT_ERROR;
                }
            }
            catch (EOFException e)
            {
                /* 익셉션 발생 이유 설명 및 스택 트레이스 복사 */
                EOFException exception = new EOFException(EXCEPTION_STRING.EXCEPTION_DESERIALIZE_FAIL);
                exception.setStackTrace(e.getStackTrace());
                super.IsExceptionPrintingAndWriteLog(exception);
                return ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_FORMAT_ERROR;
            }
        }
        return ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_REQUEST_SUCCESSFULLY_PROCESSED;
    }

    /**
     * @return 구조체의 크기를 반환
     */
    public int GetSize()
    {
        if(KeyStruct == null)
        {
            WriteErrorLog("k_struct is null");
            return super.ERROR_CODE;
        }

        int nStructSize = COMMON_SIZE.EMPTY;
        for(OnlineKeyStruct object : this.KeyStruct)
        {
            nStructSize += object.GetSize();
        }

        return ONLINE_KEY_SIZE.REQ_NUM_SIZE + nStructSize;
    }

    public byte[] GetReq_num()
    {
        return this.reqNum;
    }

    public void SetReqNum(byte[] reqNum)
    {
        this.reqNum = super.SafeSetByteArray(this.reqNum,reqNum);
    }

    public OnlineKeyStruct[] GetK_struct()
    {
        return this.KeyStruct;
    }

    public void SetKeyStruct(OnlineKeyStruct[] KeyStruct)
    {
        this.KeyStruct = KeyStruct;
    }


    public static void main(String[] args)
    {
        byte[] bAddKeySampleMessage =
                {
                        0x00,0x01, // REQ// SIZE
                        // k struct
                        0x18, // LENGTH
                        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08, // IdentifierKey
                        0x09,0x0a,0x0b,0x0c, // etcs id
                        0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10, // kmac
                        0x00,0x02, // peerNum
                        0x11,0x11,0x11,0x11, // peer 1
                        0x12,0x12,0x12,0x12, // peer 2
                        0x13,0x13,0x13,0x13,0x14,0x14,0x14,0x14, // valid_period
                };
        try
        {
            AddKey addKey = new AddKey(bAddKeySampleMessage);
            for(byte b : addKey.GetK_struct()[0].GetEtcsIdPeer()[1].EncodeObject())
            {
                System.out.printf("%02X ", b);
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }
}
