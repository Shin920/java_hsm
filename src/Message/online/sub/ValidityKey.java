package Message.online.sub;

import Message.CodecUtil;
import Message.constant.Common.*;
import Message.constant.Online.*;
import Message.ValidPeriod;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;

public class ValidityKey extends CodecUtil
{
    private IdentifierKey Identifier = new IdentifierKey();
    private ValidPeriod Validity = new ValidPeriod();

    public ValidityKey() {}

    /**
     * 기본 생성자
     * @param identifier Structure that uniquely identifies a key
     * @param validity Validity period
     */
    public ValidityKey(IdentifierKey identifier, ValidPeriod validity)
    {
        this.Identifier = identifier;
        this.Validity = validity;
    }

    /**
     * 바이트 배열을 통해 구조체 초기화
     * @param bValidityKeyMessage 메시지 패킷
     * @throws IllegalArgumentException 발생 가능한 예외처리
     */
    public ValidityKey(byte[] bValidityKeyMessage) throws IllegalArgumentException
    {
        if(DecodeMessage(bValidityKeyMessage) != ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_REQUEST_SUCCESSFULLY_PROCESSED)
        {
            throw new IllegalArgumentException(EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
        }
    }

    /**
     * 바이트 배열을 통해 구조체 초기화
     * @param bValidityKeyMessage 메시지 패킷
     */
    public int DecodeMessage(byte[] bValidityKeyMessage)
    {
        try
        {
            return DeserializeFromBytes(bValidityKeyMessage);
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
                    this.Identifier.EncodeObject(),
                    this.Validity.EncodeObject()
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
                byte[] bIdentifierBuffer = new byte[this.Identifier.GetSize()];
                dis.readFully(bIdentifierBuffer);
                this.Identifier.DecodeMessage(bIdentifierBuffer);

                byte[] bValidityBuffer = new byte[this.Validity.GetSize()];
                dis.readFully(bValidityBuffer);
                this.Validity.DecodeMessage(bValidityBuffer);

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
        return this.Identifier.GetSize() + this.Validity.GetSize();
    }

    public IdentifierKey GetIdentifier()
    {
        return this.Identifier;
    }

    public void SetIdentifier(IdentifierKey identifier)
    {
        this.Identifier = identifier;
    }

    public ValidPeriod GetValidity()
    {
        return this.Validity;
    }

    public void SetValidity(ValidPeriod validity)
    {
        this.Validity = validity;
    }

    public static void main(String[] args)
    {
        byte[] bValidityKeyMessage =
                {
                        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07, // identifier
                        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f, // validPeriod
                };

        try
        {
            ValidityKey validityKey = new ValidityKey(bValidityKeyMessage);
            for(byte b : validityKey.GetValidity().GetFrom())
            {
                System.out.printf("%02X ", b);
            }
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }

}
