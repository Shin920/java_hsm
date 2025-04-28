package Message.offline.entity;

import Message.CodecUtil;
import Message.constant.Common.*;
import Message.constant.Offline.*;
import java.io.*;


/**
 * Structure of KEY_MESSAGE_INSTALL_TRANS_KEY_STRUCT Request
 *
 * @field length -> The length of the KTRANS key to be installed
 * @field kt_num -> Serial number of the distributed KTRANS.
 * @field ktrans -> Unencrypted KTRANS1(24), Unencrypted KTRANS2(24)
 * @field cbc_mac -> Message authentication code for the message.
 */
public class InstallTransportKey extends CodecUtil
{
    private byte length;
    private byte[] serialNumber = new byte[OFFLINE_KEY_MESSAGE_SIZE.KT_NUM_SIZE];
    private byte[] ktrans = new byte[OFFLINE_KEY_MESSAGE_SIZE.KTRANS_SIZE];
    private byte[] cbcMac = new byte[COMMON_SIZE.CBC_MAC_SIZE];

    public InstallTransportKey() { }

    /**
     * 기본 생성자
     * @param length Total length of the transport keys (48 octets for KTRANS1 + KTRANS2)
     * @param serialNumber Serial number of the distributed KTRANS.
     * @param ktrans KTRANS1 + KTRANS2
     * @param cbcMac The CBC-MAC shall be calculated over the complete message from octet 1 up to but excluding the CBC-MAC field using the predefined key
     */
    public InstallTransportKey(byte length, byte[] serialNumber, byte[] ktrans, byte[] cbcMac)
    {
        SetLength(length);
        SetSerialNumber(serialNumber);
        SetKtrans(ktrans);
        SetCbcMac(cbcMac);
    }

    /**
     * Initialize the class KEY_MESSAGE_INSTALL_TRANS_KEY_STRUCT
     * @param bInstallTransKeyMessage the byte array containing the data to initialize the fields
     */
    public InstallTransportKey(byte[] bInstallTransKeyMessage) throws IllegalArgumentException
    {
        if(DecodeMessage(bInstallTransKeyMessage) != OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_SUCCESSFULLY_PROCESSED)
        {
            throw new IllegalArgumentException(EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
        }
    }

    /**
     * Initialize the class KEY_MESSAGE_INSTALL_TRANS_KEY_STRUCT
     * @param bInstallTransKeyMessage the byte array containing the data to initialize the fields
     * @return serialize to KEY_MESSAGE_DELETE_ALL_STRUCT values
     */
    public int DecodeMessage(byte[] bInstallTransKeyMessage)
    {
        try
        {
            return DeserializeFromBytes(bInstallTransKeyMessage);
        }
        catch (Exception e)
        {
            super.IsExceptionPrintingAndWriteLog(e);
            return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_ETC_ERROR;
        }
    }

    /**
     * KEY_MESSAGE_INSTALL_TRANS_KEY_STRUCT Class Returns a serialized value.
     * @return serialize to KEY_MESSAGE_INSTALL_TRANS_KEY_STRUCT values
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

    /**
     *
     * @return get All fields instance size
     */
    public int GetSize()
    {
        return OFFLINE_KEY_MESSAGE_SIZE.LENGTH_FILED_SIZE + serialNumber.length + ktrans.length + cbcMac.length;
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
            try
            { /* EOF check */
                this.length = dis.readByte();
                dis.readFully(this.serialNumber);
                dis.readFully(this.ktrans);
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
                new byte[]{this.length},
                this.serialNumber,
                this.ktrans,
                this.cbcMac
        );
    }

    /* Getter, Setter */
    public byte GetLength()
    {
        return length;
    }

    public void SetLength(byte length)
    {
        this.length = length;
    }

    public byte[] GetSerialNumber()
    {
        return this.serialNumber;
    }

    public void SetSerialNumber(byte[] kt_num)
    {
        this.serialNumber = super.SafeSetByteArray(this.serialNumber,kt_num);
    }

    public byte[] GetKtrans()
    {
        return this.ktrans;
    }
    /**
     * ktrans(48bytes) -> Unencrypted KTRANS1(24), Unencrypted KTRANS2(24)
     * */
    public void SetKtrans(byte[] ktrans)
    {
        this.ktrans = super.SafeSetByteArray(this.ktrans,ktrans);
    }

    public byte[] GetCbcMac()
    {
        return this.cbcMac;
    }

    public void SetCbcMac(byte[] cbc_mac)
    {
        this.cbcMac = super.SafeSetByteArray(this.cbcMac,cbc_mac);
    }
}