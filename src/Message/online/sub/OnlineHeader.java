package Message.online.sub;

import Message.CodecUtil;
import Message.constant.Online;
import Message.constant.Online.*;
import Message.constant.Common;
import Message.EtcsInfo;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;



/**
 * Message Header used in all messages.
 */
public class OnlineHeader extends CodecUtil
{
    private byte[] messageLength = new byte[ONLINE_KEY_SIZE.HEADER_LENGTH_SIZE]; /* 20 .. 5000 */
    private final byte interfaceVersion = Online.ONLINE_INTERFACE_VERSION; /* interface version value 2 고정*/
    private EtcsInfo ReceiverId = new EtcsInfo();
    private EtcsInfo SenderId = new EtcsInfo();
    private byte[] transactionNum = new byte[ONLINE_KEY_SIZE.TRANSACTION_SIZE];
    private byte[] sequenceNum = new byte[ONLINE_KEY_SIZE.SEQUENCE_SIZE];
    private byte messageType = (byte)0xFF;

    public OnlineHeader() {}

    /**
     * 기본 생성자 (인터페이스 버전은 2 고정)
     * @param messageLength Total length of this message including header and body in bytes. [20..5000]
     * @param receiverId  The unique identifier of the intended recipient of the message.
     * @param senderId  The unique identifier of the intended recipient of the message.
     * @param transactionNum 트랜잭션번호
     *                       <p> not 0 : The Transaction Number identifies a transaction with a particular set of operations to be performed.
     *                       The Transaction Number of the message being responded to shall be used as Transaction Number in the response.
     *                       <p>Transaction Number to be used in messages that do not require a reply, are not a reply to a request or are a notification response reporting a transaction or sequence number mismatch:
     *  NOTIF_SESSION_INIT
     *  NOTIF_END_OF_UPDATE
     *  NOTIF_RESPONSE (Transaction Number mismatch or Sequence Number mismatch)
     * @param sequenceNum The Sequence Number allows checking messages for sequence errors, i.e. lost or repeated messages. The sequence number shall wrap around to 0 after 65535.
     * @param messageType Type of ONLINE_KEY_MESSAGE_TYPE
     */
    public OnlineHeader(byte[] messageLength, EtcsInfo receiverId, EtcsInfo senderId, byte[] transactionNum, byte[] sequenceNum, byte messageType)
    {
        SetMessageLength(messageLength);
        SetReceiverId(receiverId);
        SetSenderId(senderId);
        SetTransactionNum(transactionNum);
        SetSequenceNum(sequenceNum);
        SetMessageType(messageType);
    }

    /**
     * 바이트 배열을 통해 클래스 초기화
     * @param bHeaderMessage 메시지 패킷
     * @throws IllegalArgumentException 발생 가능한 예외처리
     */
    public OnlineHeader(byte[] bHeaderMessage) throws IllegalArgumentException
    {
        if(DecodeMessage(bHeaderMessage) != ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_REQUEST_SUCCESSFULLY_PROCESSED)
        {
            throw new IllegalArgumentException(Common.EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
        }
    }

    /**
     * 바이트 배열을 통해 클래스 초기화
     * @param bHeaderMessage 메시지 패킷
     */
    public int DecodeMessage(byte[] bHeaderMessage)
    {
        try
        {
            return DeserializeFromBytes(bHeaderMessage);
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
            return super.SerializeMultipleByteArrays(
                    this.messageLength,
                    new byte[]{this.interfaceVersion},
                    this.ReceiverId.EncodeObject(),
                    this.SenderId.EncodeObject(),
                    this.transactionNum,
                    this.sequenceNum,
                    new byte[]{this.messageType}
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
        if (byteArrayInputStream == null || byteArrayInputStream.length == Common.COMMON_SIZE.EMPTY)
        {
            super.IsExceptionPrintingAndWriteLog(new IllegalArgumentException("Input stream is null or empty"));
            return ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_FORMAT_ERROR;
        }

        try (ByteArrayInputStream bais = new ByteArrayInputStream(byteArrayInputStream);
             DataInputStream dis = new DataInputStream(bais))
        {
            try  /* EOF Check */
            {
                dis.readFully(this.messageLength);
                int nMessageLength = super.ConvertByteArrayToInt(this.messageLength);
                if( !( (nMessageLength >= 20) && (nMessageLength <= 5000) ) ) /* 길이 체크 */
                {
                    IsExceptionPrintingAndWriteLog(new IllegalArgumentException("[OnlineHeader] messageLength size error It doesn't belong between 20..5000"));
                    return ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_MASSAGE_LENGTH_ERROR;
                }

                /* 인터페이스 버전이 2가 아니라면 경고 * 디코딩 프로세스를 종료시키진 않음 */
                if( dis.readByte() != this.interfaceVersion) /* 인터페이스 버전 체크 */
                {
                    String strError = String.format("[OnlineHeader] Version value is not %d", Online.ONLINE_INTERFACE_VERSION);
                    IsExceptionPrintingAndWriteLog(new IllegalArgumentException(strError));
                    return ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_UNSUPPORTED_IF_VERSION;
                }

                byte[] bEtcsIdReceiver = new byte[Common.COMMON_SIZE.ETCS_STRUCT_SIZE];
                byte[] bEtcsIdSender = new byte[Common.COMMON_SIZE.ETCS_STRUCT_SIZE];
                dis.readFully(bEtcsIdReceiver);
                dis.readFully(bEtcsIdSender);
                this.ReceiverId.DecodeMessage(bEtcsIdReceiver);
                this.SenderId.DecodeMessage(bEtcsIdSender);

                dis.readFully(this.transactionNum);
                if(super.ConvertByteArrayToInt(this.transactionNum) == 0)
                {
                    IsExceptionPrintingAndWriteLog(new IllegalArgumentException("[OnlineHeader] Transaction Number is not 0"));
                    return ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_FORMAT_ERROR;
                }

                dis.readFully(this.sequenceNum);
                int nSequenceNum = super.ConvertByteArrayToInt(this.sequenceNum);
                if(!(nSequenceNum >= 0 && nSequenceNum <= 65535))
                {
                    IsExceptionPrintingAndWriteLog(new IllegalArgumentException("[OnlineHeader] sequenceNum value error"));
                    return ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_FORMAT_ERROR;
                }

                this.messageType = dis.readByte();
                if(!CheckOnlineKeyMsgType(this.messageType))
                {
                    return ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_REQUEST_NOT_SUPPORTED;
                }


                /* 스트림에 남은 바이트가 있는지 확인 */
                if (dis.available() > Common.COMMON_SIZE.EMPTY)
                {
                    IsExceptionPrintingAndWriteLog( new IllegalArgumentException(Common.EXCEPTION_STRING.EXCEPTION_EXTRA_BYTE));
                    return ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_FORMAT_ERROR;
                }
            }
            catch (EOFException e)
            {
                /* 익셉션 발생 이유 설명 및 스택 트레이스 복사 */
                EOFException exception = new EOFException(Common.EXCEPTION_STRING.EXCEPTION_DESERIALIZE_FAIL);
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
        return this.messageLength.length + ONLINE_KEY_SIZE.VERSION_SIZE + this.ReceiverId.GetSize() +
                this.SenderId.GetSize() + this.transactionNum.length + this.sequenceNum.length + ONLINE_KEY_SIZE.MSG_TYPE_SIZE;
    }

    public byte[] GetMessageLength()
    {
        return this.messageLength;
    }

    public void SetMessageLength(byte[] messageLength)
    {
        int nMessageLength = super.ConvertByteArrayToInt(messageLength);
        if(!((nMessageLength >= 20) && (nMessageLength <= 5000))) /* 범위 체크 */
        {
            IsExceptionPrintingAndWriteLog(new IllegalArgumentException("[OnlineHeader] messageLength size error It doesn't belong between 20..5000"));
        }

        this.messageLength = super.SafeSetByteArray(this.messageLength,messageLength);
    }

    public byte GetInterfaceVersion()
    {
        return this.interfaceVersion;
    }

    public EtcsInfo GetReceiverId()
    {
        return this.ReceiverId;
    }

    public void SetReceiverId(EtcsInfo receiverId)
    {
        this.ReceiverId = receiverId;
    }

    public EtcsInfo GetSenderId()
    {
        return this.SenderId;
    }

    public void SetSenderId(EtcsInfo senderId)
    {
        this.SenderId = senderId;
    }

    public byte[] GetTransactionNum()
    {
        return this.transactionNum;
    }

    public void SetTransactionNum(byte[] transactionNum)
    {
        this.transactionNum = super.SafeSetByteArray(this.transactionNum,transactionNum);
    }

    public byte[] GetSequenceNum()
    {
        return this.sequenceNum;
    }

    public void SetSequenceNum(byte[] sequenceNum)
    {
        int nSequenceNum = super.ConvertByteArrayToInt(this.sequenceNum);
        if((nSequenceNum >= 0 && nSequenceNum <= 65535))
        {
            this.sequenceNum = super.SafeSetByteArray(this.sequenceNum, sequenceNum);
        }
        else
        {
            IsExceptionPrintingAndWriteLog(new IllegalArgumentException("[OnlineHeader] sequenceNum value error"));
        }
    }

    public byte GetMessageType()
    {
        return this.messageType;
    }

    public void SetMessageType(byte messageType)
    {
        this.messageType = messageType;
        if(!CheckOnlineKeyMsgType(this.messageType))
        {
            IsExceptionPrintingAndWriteLog(new IllegalArgumentException("[OnlineHeader] messageType value Error Type is not belong to ONLINE_KEY_MESSAGE_TYPE"));
        }
    }

    public static void main(String[] args)
    {
        byte[] bOnlineHeaderMessage =
                {
                        0x00,0x00,0x01,0x00,  // Length
                        0x02, // if version
                        0x00,0x01,0x02,0x03, //id1
                        0x04,0x05,0x06,0x07,  //id2
                        0x08,0x09,0x0a,0x0b, //tnum
                        0x0c,0x0d, // snum
                        0x00 // msg Type
                };
        try
        {
            OnlineHeader header = new OnlineHeader(bOnlineHeaderMessage);
            for(byte b : header.GetTransactionNum())
            {
                System.out.printf("%02X ",b);
            }
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }
}

