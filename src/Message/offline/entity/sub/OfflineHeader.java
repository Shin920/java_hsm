package Message.offline.entity.sub;

import Message.CodecUtil;
import Message.EtcsInfo;
import Message.constant.Offline;
import Message.constant.Common;
import Message.constant.Offline.*;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;

/***
 * Offline Key Message 의 헤더
 * <p>
 * msg_type 필드값에 따라 Body 생성됨
 */
public class OfflineHeader extends CodecUtil
{
    private byte[] length = new byte[OFFLINE_KEY_MESSAGE_SIZE.LENGTH_SIZE];
    private byte version = Offline.OFFLINE_KMC_VERSION;
    private EtcsInfo receiver = new EtcsInfo();
    private EtcsInfo sender = new EtcsInfo();
    private byte[] transaction = new byte[OFFLINE_KEY_MESSAGE_SIZE.TRANSACTION_SIZE];
    private byte[] sequence = new byte[OFFLINE_KEY_MESSAGE_SIZE.SEQUENCE_SIZE];
    private byte authAlgo = Offline.AUTH_ALGO_3DES;
    private byte[] serial = new byte[OFFLINE_KEY_MESSAGE_SIZE.SERIAL_SIZE];
    private byte msgType = (byte)0xFF; /* DEFINED.OFFLINE_KEY_MESSAGE_TYPE value */

    public OfflineHeader() {}

    /**
     * header 구조체 기본 생성자
     * @param length  Total length of the message including the length field.
     * @param version Version of the interface
     * @param receiver The unique identification of the receiver contains the ETCS ID expanded of the ETCS entity in the case of key management requests, and of the KMC for notifications
     * @param sender The unique identification of the message sender contains the ETCS ID expanded of the KMC in the case of key management requests, and the ETCS ID of the processing entity for notifications
     * @param transaction The transaction number enables the KMC to establish request - notification relations
     * @param sequence The ETCS entity expects a sequence number which is equal to the sequence number included in the last received request incremented by one except in the following
     * @param authAlgo Algorithm used for message
     * @param serial Serial number of KTRANS that has been used for MAC calculation and encryption
     * @param msgType This parameter identifies the key message type
     */
    public OfflineHeader(byte[] length, byte version, EtcsInfo receiver, EtcsInfo sender, byte[] transaction, byte[] sequence, byte authAlgo, byte[] serial, byte msgType)
    {
        SetLength(length);
        SetVersion(version);
        SetReceiver(receiver);
        SetSender(sender);
        SetTransaction(transaction);
        SetSequence(sequence);
        SetAuthAlgo(authAlgo);
        SetSerial(serial);
        SetMsgType(msgType);
    }

    /***
     * 직렬화된 바이트 배열을 통해 초기화 진행
     * @param bHeaderInformation 직렬화된 바이트 배열
     */
    public OfflineHeader(byte[] bHeaderInformation) throws IllegalArgumentException
    {
        if(DecodeMessage(bHeaderInformation) != OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_SUCCESSFULLY_PROCESSED)
        {
            throw new IllegalArgumentException(Common.EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
        }
    }

    /***
     * 직렬화된 바이트 배열을 통해 초기화 진행
     * @param bHeaderInformation 직렬화된 바이트 배열
     * @return <p><b>발생 가능한 Result Code[0,3,11,12,13,18]
     */
    public int DecodeMessage(byte[] bHeaderInformation)
    {
        try
        {
            return DeserializeFromBytes(bHeaderInformation);
        }
        catch (Exception e)
        {
            super.IsExceptionPrintingAndWriteLog(e);
            return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_ETC_ERROR;
        }
    }

    /***
     *
     * @return 클래스 필드 인스턴스들의 값을 바이트 배열로 직렬화하여 반환
     */
    public byte[] EncodeObject() {
        try
        {
            return SerializeToBytes();
        }
        catch (IOException e)
        {
            super.IsExceptionPrintingAndWriteLog(e);
            return super.MakeErrorPacket(GetSize());
        }
    }

    private int DeserializeFromBytes(byte[] byteArrayInputStream) throws IOException
    {
        if (byteArrayInputStream == null || byteArrayInputStream.length == Common.COMMON_SIZE.EMPTY)
        {
            super.IsExceptionPrintingAndWriteLog(new IllegalArgumentException("Input stream is null or empty"));
            return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_MESSAGE_LENGTH_ERROR;
        }

        try (ByteArrayInputStream bais = new ByteArrayInputStream(byteArrayInputStream);
             DataInputStream dis = new DataInputStream(bais))
        {
            try
            { /* EOF Check */
                dis.readFully(this.length);
                this.version = dis.readByte();
                if(this.version != Offline.OFFLINE_KMC_VERSION) /* 인터페이스 버전 체크 */
                {
                    IsExceptionPrintingAndWriteLog( new IllegalArgumentException("[OfflineHeader Decode] version value error "));
                    return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_INTERFACE_VERSION_NOT_SUPPORTED;
                }

                byte[] bEtcsId = new byte[Common.COMMON_SIZE.ETCS_STRUCT_SIZE];
                dis.readFully(bEtcsId);
                this.receiver.DecodeMessage(bEtcsId);

                byte[] bEtcsId2 = new byte[Common.COMMON_SIZE.ETCS_STRUCT_SIZE];
                dis.readFully(bEtcsId2);
                this.sender.DecodeMessage(bEtcsId2);

                dis.readFully(this.transaction);
                dis.readFully(this.sequence);

                this.authAlgo = dis.readByte();
                if(this.authAlgo != Offline.AUTH_ALGO_3DES) /* 인증 알고리즘 체크 */
                {
                    IsExceptionPrintingAndWriteLog( new IllegalArgumentException("[OfflineHeader Decode] authAlgo value Error "));
                    return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_AUTHENTICATION_ALGORITHM_NOT_IMPLEMENTED;
                }
                dis.readFully(this.serial);
                this.msgType = dis.readByte();
                /* 헤더에 삽입된 메시지 타입이 OFFLINE_KEY_MESSAGE_TYPE 에 속하는지 맞는지 체크*/
                if (!CheckOfflineKeyMsgType(this.msgType)) /* 메시지 타입 체크 */
                {
                    IsExceptionPrintingAndWriteLog( new IllegalArgumentException("[OfflineHeader Decode] This type does not belong to OFFLINE_KEY_MESSAGE_TYPE"));
                    return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_NOT_SUPPORTED;
                }

                /* 스트림에 남은 바이트가 있는지 확인 */
                if (dis.available() > Common.COMMON_SIZE.EMPTY)
                {
                    IsExceptionPrintingAndWriteLog(new IllegalArgumentException(Common.EXCEPTION_STRING.EXCEPTION_EXTRA_BYTE));
                    return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_INCONSISTENCY_DETECTED_IN_THE_RECEIVED_REQUEST;
                }
            }
            catch (EOFException e)
            {
                /* 익셉션 발생 이유 설명 및 스택 트레이스 복사 */
                EOFException exception = new EOFException(Common.EXCEPTION_STRING.EXCEPTION_DESERIALIZE_FAIL);
                exception.setStackTrace(e.getStackTrace());
                super.IsExceptionPrintingAndWriteLog(exception);
                return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_INCONSISTENCY_DETECTED_IN_THE_RECEIVED_REQUEST;
            }
        }

        return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_SUCCESSFULLY_PROCESSED;
    }

    /* 객체를 바이트 배열로 직렬화 */
    private byte[] SerializeToBytes() throws IOException
    {
        return super.SerializeMultipleByteArrays(
                this.length,
                new byte[]{this.version},
                this.receiver.EncodeObject(),
                this.sender.EncodeObject(),
                this.transaction,
                this.sequence,
                new byte[]{this.authAlgo},
                this.serial,
                new byte[]{this.msgType}
        );
    }
    /**
     * 필드 인스턴스들의 총 크기
     * */
    public int GetSize()
    {
        return this.length.length + OFFLINE_KEY_MESSAGE_SIZE.VERSION_SIZE + this.receiver.GetSize() + this.sender.GetSize() +
                this.transaction.length + this.sequence.length+ OFFLINE_KEY_MESSAGE_SIZE.E_ALGO_SIZE + this.serial.length + OFFLINE_KEY_MESSAGE_SIZE.MSG_TYPE_SIZE;
    }

    /* Getters and setters with length checks for byte arrays */

    /**
     * Length 필드의 값
     * */
    public byte[] GetLength()
    {
        return length;
    }

    public void SetLength(byte[] length)
    {
        this.length = super.SafeSetByteArray(this.length,length);
    }

    public byte GetVersion()
    {
        return version;
    }

    public void SetVersion(byte version)
    {
        this.version = version;
    }

    public EtcsInfo GetReceiver()
    {
        return receiver;
    }

    public void SetReceiver(EtcsInfo receiver)
    {
        this.receiver = receiver;
    }

    public EtcsInfo GetSender()
    {
        return sender;
    }

    public void SetSender(EtcsInfo sender)
    {
        this.sender = sender;
    }

    public byte[] GetTransaction()
    {
        return transaction;
    }

    public void SetTransaction(byte[] transaction)
    {
        this.transaction = super.SafeSetByteArray(this.transaction,transaction);
    }

    public byte GetAuthAlgo()
    {
        return authAlgo;
    }

    public void SetAuthAlgo(byte auth_algo)
    {
        this.authAlgo = auth_algo;
    }

    public byte[] GetSerial()
    {
        return serial;
    }

    public void SetSerial(byte[] serial)
    {
        this.serial = super.SafeSetByteArray(this.serial,serial);
    }
    /**
     * DEFINED.OFFLINE_KEY_MESSAGE_TYPE value
     * */
    public byte GetMsgType()
    {
        return msgType;
    }
    /**
     * DEFINED.OFFLINE_KEY_MESSAGE_TYPE value
     * */
    public void SetMsgType(byte msg_type)
    {

        this.msgType = CheckOfflineKeyMsgType(msg_type) ? msg_type : ERROR_BYTE;
    }

    public byte[] GetSequence()
    {
        return sequence;
    }

    public void SetSequence(byte[] sequence)
    {
        this.sequence = sequence;
    }
}