package Message.offline.entity;

import Message.CodecUtil;
import Message.EtcsInfo;
import Message.ValidPeriod;
import Message.constant.Common.*;
import Message.constant.Offline.*;
import java.io.*;

public class UpdateKeyValidityPeriod extends CodecUtil
{
    private EtcsInfo KmEtcsIdExp =new EtcsInfo();
    private byte[] serialNumber = new byte[OFFLINE_KEY_MESSAGE_SIZE.SERIAL_SIZE];
    private ValidPeriod validPeriod = new ValidPeriod();
    private byte[] cbcMac = new byte[COMMON_SIZE.CBC_MAC_SIZE];

    /**
     * 기본 생성자
     * @param kmEtcsIdExp ETCS ID type and ETCS ID of the KMC that issued the authentication key to be updated
     * @param serialNumber Unique serial number of the triple-key of which the key validity period has to be updated (together with the KM-ETCS-ID-EXP, this identifies the triple-key unambiguously)
     * @param validPeriod Updated validity period
     * @param cbcMac The CBC-MAC shall be calculated over the complete message from octet 1 up to but excluding the CBC-MAC field using transport key KTRANS1
     */
    public UpdateKeyValidityPeriod(EtcsInfo kmEtcsIdExp, byte[] serialNumber, ValidPeriod validPeriod, byte[] cbcMac)
    {
        SetKmEtcsIdExp(kmEtcsIdExp);
        SetSerialNumber(serialNumber);
        SetValidPeriod(validPeriod);
        SetCbcMac(cbcMac);
    }

    public UpdateKeyValidityPeriod() { }

    /**
     * * Initialize
     * @param bUpdateKeyValidityMessage the byte array containing the data to initialize the fields
     */
    public UpdateKeyValidityPeriod(byte[] bUpdateKeyValidityMessage) throws IllegalArgumentException
    {
        if(DecodeMessage(bUpdateKeyValidityMessage) != OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_SUCCESSFULLY_PROCESSED)
        {
            throw new IllegalArgumentException(EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
        }
    }
    /**
     * * Initialize
     * @param bUpdateKeyValidityMessage the byte array containing the data to initialize the fields
     * @return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE [0,12,13]
     */
    public int DecodeMessage(byte[] bUpdateKeyValidityMessage)
    {
        try
        {
            return DeserializeFromBytes(bUpdateKeyValidityMessage);
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

    /***
     *
     * @return 구조체의 크기를 반환
     */
    public int GetSize()
    {
        return KmEtcsIdExp.GetSize() + this.serialNumber.length + this.validPeriod.GetSize() + this.cbcMac.length;
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
                byte[] bEtcsId = new byte[COMMON_SIZE.ETCS_STRUCT_SIZE];
                dis.readFully(bEtcsId);
                this.KmEtcsIdExp.DecodeMessage(bEtcsId);

                dis.readFully(this.serialNumber);

                byte[] bValid = new byte[COMMON_SIZE.VALID_PERIOD_STRUCT_SIZE];
                dis.readFully(bValid);
                this.KmEtcsIdExp.DecodeMessage(bValid);

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
                this.serialNumber,
                this.validPeriod.EncodeObject(),
                this.cbcMac
        );
    }

    public EtcsInfo GetKmEtcsIdExp()
    {
        return this.KmEtcsIdExp;
    }

    public void SetKmEtcsIdExp(EtcsInfo kmEtcsIdExp)
    {
        this.KmEtcsIdExp = kmEtcsIdExp;
    }

    public byte[] GetSerialNumber()
    {
        return this.serialNumber;
    }

    public void SetSerialNumber(byte[] serialNumber)
    {
        this.serialNumber = super.SafeSetByteArray(this.serialNumber,serialNumber);
    }

    public ValidPeriod GetValidPeriod()
    {
        return this.validPeriod;
    }

    public void SetValidPeriod(ValidPeriod validPeriod)
    {
        this.validPeriod = validPeriod;
    }

    public byte[] GetCbcMac()
    {
        return this.cbcMac;
    }

    public void SetCbcMac(byte[] cbcMac)
    {
        this.cbcMac = super.SafeSetByteArray(this.cbcMac,cbcMac);
    }
}

