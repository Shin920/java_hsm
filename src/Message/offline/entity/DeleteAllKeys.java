package Message.offline.entity;

import Message.CodecUtil;
import Message.constant.Common.*;
import Message.constant.Offline.*;
import java.io.*;

/**
 * Structure of KEY_MESSAGE_DELETE_ALL_STRUCT Request
 *
 * @field key_type -> This field indicates the type of key to be deleted. Only the keys distributed by the KMC shall be considered
 * @field cbc_mac -> Message authentication code for the message.
 * */
public class DeleteAllKeys extends CodecUtil
{
    private byte keyType;
    private byte[] cbcMac = new byte[COMMON_SIZE.CBC_MAC_SIZE];

    /**
     * Structure of DELETE_ALL_KEYS Request
     * @param keyType This field indicates the type of key to be deleted. Only the keys distributed by the KMC shall be considered
     * @param cbcMac The CBC-MAC shall be calculated over the complete message from octet 1 up to but excluding the CBC-MAC field using transport key KTRANS1
     */
    public DeleteAllKeys(byte keyType, byte[] cbcMac)
    {
        SetKeyType(keyType);
        SetCbcMac(cbcMac);
    }

    public DeleteAllKeys() {}

    /**
     * Initialize the class
     * @param bDeleteAllMessage the byte array containing the data to initialize the fields
     */
    public DeleteAllKeys(byte[] bDeleteAllMessage) throws IllegalArgumentException
    {
        if(DecodeMessage(bDeleteAllMessage) != OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_SUCCESSFULLY_PROCESSED)
        {
            throw new IllegalArgumentException(EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
        }
    }

    /**
     * Initialize the class
     * @param bDeleteAllMessage the byte array containing the data to initialize the fields
     * @return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE [0,12,13]
     */
    public int DecodeMessage(byte[] bDeleteAllMessage)
    {
        try
        {
            return DeserializeFromBytes(bDeleteAllMessage);
        }
        catch (Exception e)
        {
            super.IsExceptionPrintingAndWriteLog(e);
            return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_ETC_ERROR;
        }
    }

    /**
     * KEY_MESSAGE_ADD_AUTHENTICATION_STRUCT Class Returns a serialized value.
     * Check whether the key_type value is the correct value.
     * @return serialize to KEY_MESSAGE_DELETE_ALL_STRUCT values
     */
    public byte[] EncodeObject()
    {
        try
        {
            switch (this.keyType)
            {
                case KEY_TYPE.KMAC,KEY_TYPE.KTRANS,KEY_TYPE.KMAC_KTRANS ->
                {
                    return SerializeToBytes();
                }
                default ->
                {
                    throw new IOException("key_type value Error");
                }
            }
        }
        catch (IOException e)
        {
            super.IsExceptionPrintingAndWriteLog(e);
            return super.MakeErrorPacket(GetSize());
        }
    }

    /**
     *
     * @return get All fields instance size
     */
    public int GetSize()
    {
        return OFFLINE_KEY_MESSAGE_SIZE.KEY_TYPE_SIZE + cbcMac.length;
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
            try
            { /* EOF check */
                this.keyType = dis.readByte();
                /*   0000 0001 KMAC
                 *   0000 0010 KTRANS
                 **  0000 0011 KMAC + KTRANS */
                if(this.keyType > 0b00000011)
                {
                    IsExceptionPrintingAndWriteLog(new IllegalArgumentException("[DeleteAllKeys] keyType value error "));
                    return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_INCONSISTENCY_DETECTED_IN_THE_RECEIVED_REQUEST;
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

    /* Byte-serialize field instance values */
    private byte[] SerializeToBytes() throws IOException
    {
        return super.SerializeMultipleByteArrays(
                new byte[]{this.keyType},
                this.cbcMac);
    }

    public void SetCbcMac(byte[] CbcMac)
    {
        this.cbcMac = super.SafeSetByteArray(this.cbcMac,CbcMac);
    }

    public void SetKeyType(byte KeyType)
    {
        this.keyType = KeyType;
    }

    public byte[] GetCbcMac()
    {
        return this.cbcMac;
    }

    public byte GetKeyType()
    {
        return this.keyType;
    }
}