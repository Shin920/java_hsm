package Message.online.sub;

import Message.CodecUtil;
import Message.EtcsInfo;
import Message.constant.Common.*;
import Message.constant.Online.*;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;

public class IdentifierKey extends CodecUtil
{
    private EtcsInfo EtcsIdExp = new EtcsInfo();
    private byte[] sNum = new byte[ONLINE_KEY_SIZE.SNUM_SIZE];

    public IdentifierKey() { }

    /**
     * 기본 생성자
     * @param etcsIdExp The identity of the KMC that issued the key.
     * @param sNum The serial number of the key.
     */
    public IdentifierKey(EtcsInfo etcsIdExp, byte[] sNum)
    {
        this.EtcsIdExp = etcsIdExp;
        this.sNum = sNum;
    }

    /**
     * 바이트 배열을 통해 구조체 초기화
     * @param bIdentifierMessage 메시지 패킷
     * @throws IllegalArgumentException 발생 가능한 예외처리
     */
    public IdentifierKey(byte[] bIdentifierMessage) throws IllegalArgumentException
    {
        if(DecodeMessage(bIdentifierMessage) != ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_REQUEST_SUCCESSFULLY_PROCESSED)
        {
            throw new IllegalArgumentException(EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
        }
    }

    /**
     * 바이트 배열을 통해 구조체 초기화
     * @param bIdentifierMessage 메시지 패킷
     */
    public int DecodeMessage(byte[] bIdentifierMessage)
    {
        try
        {
            return DeserializeFromBytes(bIdentifierMessage);
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
            try /* EOF Check */
            {
                byte[] bEtcsIdBuffer = new byte[COMMON_SIZE.ETCS_STRUCT_SIZE];
                dis.readFully(bEtcsIdBuffer);
                this.EtcsIdExp.DecodeMessage(bEtcsIdBuffer);

                dis.readFully(this.sNum);

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
        return this.EtcsIdExp.GetSize() + this.sNum.length;
    }

    /** 객체를 바이트 배열로 직렬화 */
    private byte[] SerializeToBytes() throws IOException
    {
        return super.SerializeMultipleByteArrays(
                this.EtcsIdExp.EncodeObject(),
                this.sNum);
    }


    public EtcsInfo GetEtcsIdExp()
    {
        return this.EtcsIdExp;
    }

    public void SetEtcsIdExp(EtcsInfo etcsIdExp)
    {
        this.EtcsIdExp = etcsIdExp;
    }

    public byte[] GetSnum()
    {
        return this.sNum;
    }

    public void SetSnum(byte[] snum)
    {
        this.sNum = snum;
    }
}
