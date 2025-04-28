package Message.offline.entity;

import Message.CodecUtil;
import Message.offline.entity.sub.OfflineKeyStruct;
import Message.constant.Common.*;
import Message.constant.Offline.*;
import java.io.*;
import java.util.LinkedList;
import java.util.Queue;


/**
 * Structure of ADD_AUTHENTICATION_KEY Request
 *
 * @field OFFLINE_KEY_STRUCT -> K-STRUCT shall be greater or equal to ‘1’
 * @field cbc_mac -> Message authentication code for the message.
 * */
public class AddAuthenticationKey extends CodecUtil
{
    private OfflineKeyStruct[] keyStructs = null;
    private byte[] cbcMac = new byte[COMMON_SIZE.CBC_MAC_SIZE];


    /**
     * 기본 생성자
     * @param keyStructs  Key structure
     * @param cbcMac The CBC-MAC shall be calculated over the complete message from octet 1 up to but excluding the CBC-MAC field using transport key KTRANS1
     */
    public AddAuthenticationKey(OfflineKeyStruct[] keyStructs, byte[] cbcMac)
    {
        SetKeyStructs(keyStructs);
        SetCbcMac(cbcMac);
    }

    /**
     *  Be sure to set k_structs directly or use the k_struct setter method to set the value.
     */
    public AddAuthenticationKey(){}

    /**
     * Initialize the class
     * @param bAddAuthenticationMessage the byte array containing the data to initialize the fields
     */
    public AddAuthenticationKey(byte[] bAddAuthenticationMessage) throws IllegalArgumentException
    {
        if(DecodeMessage(bAddAuthenticationMessage) != OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_SUCCESSFULLY_PROCESSED)
        {
            throw new IllegalArgumentException(EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
        }
    }

    /**
     * Initialize the class
     * @param bAddAuthenticationMessage the byte array containing the data to initialize the fields
     * @return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE [0,12,13]
     */
    public int DecodeMessage(byte[] bAddAuthenticationMessage)
    {
        try
        {
            return DeserializeFromBytes(bAddAuthenticationMessage);
        }
        catch (Exception e)
        {
            super.IsExceptionPrintingAndWriteLog(e);
            return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_ETC_ERROR;
        }
    }

    /**
     * KEY_MESSAGE_ADD_AUTHENTICATION_STRUCT Class Returns a serialized value.
     * @return serialize to KEY_MESSAGE_ADD_AUTHENTICATION_STRUCT values
     */
    public byte[] EncodeObject()
    {
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

    private int DeserializeFromBytes(byte[] byteArrayInputStream) throws Exception
    {
        if (byteArrayInputStream == null || byteArrayInputStream.length == COMMON_SIZE.EMPTY)
        {
            super.IsExceptionPrintingAndWriteLog(new IllegalArgumentException("Input stream is null or empty"));
            return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_MESSAGE_LENGTH_ERROR;
        }

        try (ByteArrayInputStream bais = new ByteArrayInputStream(byteArrayInputStream);
             DataInputStream dis = new DataInputStream(bais))
        {
            try { /* EOF check */
                /* Insert K-Struct */
                Queue<byte[]> qKStruct = new LinkedList<>(); /* 직렬화된 K-struct 바이트배열을 저장할 큐 */
                do {
                    byte bLength = dis.readByte();
                    byte[] bKmcId = new byte[COMMON_SIZE.ETCS_STRUCT_SIZE];
                    dis.readFully(bKmcId);
                    byte[] bSerialNumber = new byte[OFFLINE_KEY_MESSAGE_SIZE.SERIAL_SIZE];
                    dis.readFully(bSerialNumber);
                    byte[] bEnc = new byte[OFFLINE_KEY_MESSAGE_SIZE.KMAC_SIZE];
                    dis.readFully(bEnc);
                    byte[] bPeerNum = new byte[OFFLINE_KEY_MESSAGE_SIZE.PEER_NUM_SIZE];
                    dis.readFully(bPeerNum);
                    int nPeerIdLength = ConvertByteArrayToInt(bPeerNum) * COMMON_SIZE.ETCS_STRUCT_SIZE;
                    byte[] bPeerId = new byte[nPeerIdLength];
                    dis.readFully(bPeerId);

                    byte[] bValidPeriod = new byte[COMMON_SIZE.VALID_PERIOD_STRUCT_SIZE];
                    dis.readFully(bValidPeriod);
                    qKStruct.add( /* 설정한 값들을 직렬화하여 큐에 저장 */
                            super.SerializeMultipleByteArrays(
                                    new byte[]{bLength},
                                    bKmcId,
                                    bSerialNumber,
                                    bEnc,
                                    bPeerNum,
                                    bPeerId,
                                    bValidPeriod
                            ));
                    /* 남은 크기가를 확인하고 CBC_MAC 사이즈 이하의 크기라면 K-struct 구성 종료 */
                    if (dis.available() <= COMMON_SIZE.CBC_MAC_SIZE)
                    {
                        break;
                    }
                } while (true);
                int nPacketSize = qKStruct.size();
                this.keyStructs = new OfflineKeyStruct[nPacketSize];
                for (int idx = 0; idx < nPacketSize; idx++)
                {
                    /* 큐의 바이트배열을 이용하여 구조체 생성 */
                    this.keyStructs[idx] = new OfflineKeyStruct();
                    if(this.keyStructs[idx].DecodeMessage(qKStruct.poll()) != OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_SUCCESSFULLY_PROCESSED)
                    {
                        IsExceptionPrintingAndWriteLog( new IllegalArgumentException("[AddAuthenticationKey] KeyStruct[] value error "));
                        return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_INCONSISTENCY_DETECTED_IN_THE_RECEIVED_REQUEST;
                    }
                }

                dis.readFully(this.cbcMac);

                /* 스트림에 남은 바이트가 있는지 확인 */
                if (dis.available() > COMMON_SIZE.EMPTY)
                {
                    IsExceptionPrintingAndWriteLog(new IllegalArgumentException(EXCEPTION_STRING.EXCEPTION_EXTRA_BYTE));
                    return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_INCONSISTENCY_DETECTED_IN_THE_RECEIVED_REQUEST;
                }
            }
            catch (EOFException e)
            {
                /* 익셉션 발생 이유 설명 및 스택 트레이스 복사 */
                EOFException exception = new EOFException(EXCEPTION_STRING.EXCEPTION_DESERIALIZE_FAIL);
                exception.setStackTrace(e.getStackTrace());
                super.IsExceptionPrintingAndWriteLog(exception);
                return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_INCONSISTENCY_DETECTED_IN_THE_RECEIVED_REQUEST;
            }
        }

        return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_SUCCESSFULLY_PROCESSED;
    }


    /**
     * Initialize the class through the parameter k_struct.
     * @param keyStructs Object array * size: 1~n;
     */
    public AddAuthenticationKey(OfflineKeyStruct[] keyStructs)
    {
        this.keyStructs = keyStructs;
    }

    /**
     *
     * @return get All fields instance size
     */
    public int GetSize()
    {

        try {
            if (this.keyStructs.length == COMMON_SIZE.EMPTY)
            {
                /* k_struct 가 하나도 구성되지 않았다면 예외 처리 */
                throw new IOException("K-struct is Empty");
            }

            int nSize = COMMON_SIZE.EMPTY;

            for (OfflineKeyStruct obKStruct : this.keyStructs)
            {
                nSize += obKStruct.GetSize();
            }
            return nSize + this.cbcMac.length;
        }
        catch (IOException e)
        {
            super.IsExceptionPrintingAndWriteLog(e);
            return super.ERROR_CODE;
        }

    }

    /**
     * Serializes the OFFLINE_KEY_STRUCT objects and appends the cbc_mac array.
     *
     * @return A byte array containing the serialized OFFLINE_KEY_STRUCT packets followed by the cbc_mac array.
     * @throws IOException If k_structs is null.
     */
    private byte[] SerializeToBytes() throws IOException
    {
        if(keyStructs == null)
        {
            throw new IOException("k_structs is null");
        }

        byte[] bSerializedMsg = new byte[COMMON_SIZE.EMPTY];
        for (OfflineKeyStruct kStruct : keyStructs)
        {
            bSerializedMsg = super.AddPacket(bSerializedMsg,kStruct.EncodeObject());
        }
        return super.SerializeMultipleByteArrays(bSerializedMsg, cbcMac);
    }

    public OfflineKeyStruct[] GetKeyStructs()
    {
        return keyStructs;
    }

    public void SetKeyStructs(OfflineKeyStruct[] k_structs)
    {
        this.keyStructs = k_structs;
    }

    public byte[] GetCbcMac()
    {
        return cbcMac;
    }

    public void SetCbcMac(byte[] cbc_mac)
    {
        this.cbcMac = super.SafeSetByteArray(this.cbcMac,cbc_mac);
    }
}

