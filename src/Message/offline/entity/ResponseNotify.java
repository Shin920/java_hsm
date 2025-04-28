package Message.offline.entity;

import Message.CodecUtil;
import Message.constant.Common.*;
import Message.constant.Offline.*;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;

public class ResponseNotify extends CodecUtil
{
    private byte result;
    private byte length;
    private byte[] text = null;
    private byte[] sequenceNumber = new byte[OFFLINE_KEY_MESSAGE_SIZE.SEQUENCE_SIZE];
    private byte[] cbcMac = new byte[COMMON_SIZE.CBC_MAC_SIZE];

    /**
     * 기본 생성자
     * @param result Result of request execution or confirmation of the reception. For retuned code definition see next table
     * Confirmation of reception is optional
     * @param length Set to 0 if text field is not used, maximum text length : 255 octets
     * @param text Text in ASCII format(each character coded in 1 octet, most significant bit being the bit `0´) , if any
     * @param sequenceNumber The ETCS entity expects a sequence number
     * @param cbcMac The CBC-MAC shall be calculated over the complete message from octet 1 up to but excluding the CBC-MAC field using transport key KTRANS1 or the predefined key
     */
    public ResponseNotify(byte result, byte length, byte[] text, byte[] sequenceNumber, byte[] cbcMac)
    {
        SetResult(result);
        SetLength(length);
        SetText(text);
        SetSequenceNumber(sequenceNumber);
        SetCbcMac(cbcMac);
    }

    public ResponseNotify() {}

    /**
     * Initialize the class
     * @param bResponseNotifyMessage the byte array containing the data to initialize the fields
     */
    public ResponseNotify(byte[] bResponseNotifyMessage) throws IllegalArgumentException
    {
        if(DecodeMessage(bResponseNotifyMessage) != OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_SUCCESSFULLY_PROCESSED)
        {
            throw new IllegalArgumentException(EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
        }
    }

    /**
     * Initialize the class
     * @param bResponseNotifyMessage the byte array containing the data to initialize the fields
     * @return serialize to KEY_MESSAGE_DELETE_ALL_STRUCT values
     */
    public int DecodeMessage(byte[] bResponseNotifyMessage)
    {
        try
        {
            return DeserializeFromBytes(bResponseNotifyMessage);
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
            return super.MakeErrorPacket(GetSize());
        }
    }

    /***
     *
     * @return 구조체의 사이즈 반환
     */
    public int GetSize()
    {
        return OFFLINE_KEY_MESSAGE_SIZE.RESULT_SIZE +
                (this.length == 0 ? OFFLINE_KEY_MESSAGE_SIZE.LENGTH_FILED_SIZE: OFFLINE_KEY_MESSAGE_SIZE.LENGTH_FILED_SIZE + this.length)
                + this.sequenceNumber.length + this.cbcMac.length;
    }

    /**
     * Convert ASCII code byte array to string
     * @return byte to string Value
     */
    public String GetTextFiledToString()
    {
        StringBuilder returnText = new StringBuilder();

        for(byte c : this.text)
        {
            returnText.append((char) c);
        }

        return returnText.toString();
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
                this.result = dis.readByte();
                this.length = dis.readByte();
                { /* 설정된 length 필드에 맞춰서 text 크기 할당 */
                    this.text = new byte[this.length];
                    dis.readFully(this.text);
                }

                dis.readFully(this.sequenceNumber);
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
                new byte[]{this.result},
                /* 길이조건이 0이라면 text 값은 포함시키지 않음 */
                this.length == 0 ? new byte[]{0x00} : super.AddPacket(new byte[]{this.length},this.text),
                this.sequenceNumber,
                this.cbcMac
        );
    }

    public byte GetResult()
    {
        return this.result;
    }

    public void SetResult(byte result) {
        try
        {
            if (!CheckOfflineKeyResultCode(result))
            {
                throw new IllegalArgumentException("parameter value is not Result code. please Check OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE object ");
            }
        }
        catch (IllegalArgumentException e)
        {
            super.IsExceptionPrintingAndWriteLog(e);
        }
        finally
        {
            /* 예외처리에 상관없이 파라미터 값은 적용 */
            this.result = result;
        }
    }

    public byte GetLength()
    {
        return this.length;
    }

    public void SetLength(byte length)
    {
        this.length = length;

        if( this.length == (byte) 0 )
        {
            this.text = null;
        }

        if(this.text == null)
        {
            this.text = new byte[this.length];
        }
    }

    public byte[] GetText()
    {
        return text;
    }

    public void SetText(byte[] text)
    {
        this.text = text;
        this.length = (byte)this.text.length;
    }

    public byte[] GetSequenceNumber()
    {
        return this.sequenceNumber;
    }

    public void SetSequenceNumber(byte[] sequenceNumber)
    {
        this.sequenceNumber = super.SafeSetByteArray(this.sequenceNumber,sequenceNumber);
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
