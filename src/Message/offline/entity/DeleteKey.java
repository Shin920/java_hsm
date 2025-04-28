package Message.offline.entity;

import Message.CodecUtil;
import Message.EtcsInfo;
import Message.constant.Common.*;
import Message.constant.Offline.*;
import java.io.*;

/**
 * Structure of KEY_MESSAGE_ETCS_EXP_STRUCT Request
 *
 * @field etcs_id -> ETCS ID type and ETCS ID of the KMC that issued the authentication key to be deleted
 * @field serial_number -> Unique serial number of key to be deleted (together with the KM-ETCS-ID-EXP, this identifies the triple-key unambiguously)
 * @field cbc_mac The CBC-MAC shall be calculated over the complete message from octet 1 up to but excluding the CBC-MAC field using transport key KTRANS1
 * */
public class DeleteKey extends CodecUtil
{
    private EtcsInfo KmEtcsIdExp = new EtcsInfo();
    private byte[] sNum = new byte[OFFLINE_KEY_MESSAGE_SIZE.SERIAL_SIZE];
    private byte[] cbcMac = new byte[COMMON_SIZE.CBC_MAC_SIZE];

    /**
     * 기본 생성자
     * @param KmEtcsIdExp ETCS ID type and ETCS ID of the KMC that issued the authentication key to be deleted
     * @param sNum Unique serial number of key to be deleted (together with the KM-ETCS-ID-EXP, this identifies the triple-key unambiguously)
     * @param cbcMac The CBC-MAC shall be calculated over the complete message from octet 1 up to but excluding the CBC-MAC field using transport key KTRANS1
     */
    public DeleteKey(EtcsInfo KmEtcsIdExp, byte[] sNum, byte[] cbcMac)
    {
        SetKmEtcsIdExp(KmEtcsIdExp);
        SetSerialNumber(sNum);
        SetCbcMac(cbcMac);
    }

    public DeleteKey() {}

    /**
     * * Initialize the class KEY_MESSAGE_DELETE_STRUCT
     * @param bDeleteKeyMessage the byte array containing the data to initialize the fields
     */
    public DeleteKey(byte[] bDeleteKeyMessage) throws IllegalArgumentException
    {
        if(DecodeMessage(bDeleteKeyMessage) != OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_SUCCESSFULLY_PROCESSED)
        {
            throw new IllegalArgumentException(EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
        }
    }

    /**
     * * Initialize the class KEY_MESSAGE_DELETE_STRUCT
     * @param bDeleteKeyMessage the byte array containing the data to initialize the fields
     * @return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE [0,12,13]
     */
    public int DecodeMessage(byte[] bDeleteKeyMessage)
    {
        try
        {
            return DeserializeFromBytes(bDeleteKeyMessage);
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
            return SerializeToBytes();
        }
        catch (IOException e)
        {
            super.IsExceptionPrintingAndWriteLog(e);
            return MakeErrorPacket(GetSize());
        }
    }

    /**
     *
     * @return get All fields instance size
     */
    public int GetSize()
    {
        return KmEtcsIdExp.GetSize() + sNum.length + cbcMac.length;
    }

    /* 바이트 배열을 이용하여 객체의 필드 초기화 */
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
                byte[] bEtcsIdData = new byte[COMMON_SIZE.ETCS_STRUCT_SIZE];
                dis.readFully(bEtcsIdData);
                this.KmEtcsIdExp = new EtcsInfo(bEtcsIdData);

                dis.readFully(this.sNum);
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


    /* 객체를 바이트 배열로 직렬화 */
    private byte[] SerializeToBytes() throws IOException
    {
        return super.SerializeMultipleByteArrays(
                this.KmEtcsIdExp.EncodeObject(),
                this.sNum,
                this.cbcMac);
    }

    public EtcsInfo GetKmEtcsIdExp()
    {
        return KmEtcsIdExp;
    }

    public void SetKmEtcsIdExp(EtcsInfo KmEtcsIdExp)
    {
        this.KmEtcsIdExp = KmEtcsIdExp;
    }

    public byte[] GetSerialNumber()
    {
        return sNum;
    }

    public void SetSerialNumber(byte[] serial_number)
    {
        this.sNum = super.SafeSetByteArray(this.sNum,serial_number);
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