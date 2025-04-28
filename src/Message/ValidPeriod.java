package Message;

import java.io.IOException;
import Message.constant.Common.*;

/***
 * VALID_PERIOD 구조체
 * @field from -> 시작 시간
 * @field to -> 종료 시간
 */
public class ValidPeriod extends CodecUtil
{
    private byte[] from = new byte[COMMON_SIZE.VALID_INSTANCE_SIZE];
    private byte[] to = new byte[COMMON_SIZE.VALID_INSTANCE_SIZE];

    /**
     * 기본 생성자
     * @param from 시작일자
     * @param to 종료일자
     */
    public ValidPeriod(byte[] from, byte[] to)
    {
        SetFrom(from);
        SetTo(to);
    }

    public ValidPeriod()
    {
        /* 기본 생성자 */
    }

    /**
     * 바이트 배열을 통해 구조체를 초기화
     * */
    public ValidPeriod(byte[] bValidPeriodMessage)
    {
        DecodeMessage(bValidPeriodMessage);
    }

    /**
     * 바이트 배열을 통해 구조체를 초기화
     * */
    public void DecodeMessage(byte[] bValidPeriodMessage)
    {
        if (bValidPeriodMessage.length != COMMON_SIZE.VALID_PERIOD_STRUCT_SIZE)
        {
            throw new IllegalArgumentException("Byte array must be exactly 8 bytes long.");
        }

        this.from = super.SeparationByteArray(bValidPeriodMessage,0,3);
        this.to = super.SeparationByteArray(bValidPeriodMessage,4,7);
    }

    /***
     * @return 필드 인스턴스들의 값을 직렬화한 바이트 배열
     */
    public byte[] EncodeObject()
    {
        try
        {
            return super.SerializeMultipleByteArrays(from,to);
        }
        catch (IOException e)
        {
            super.IsExceptionPrintingAndWriteLog(e);
            return super.MakeErrorPacket(GetSize());
        }
    }

    /***
     *
     * @return 구조체 크기
     */
    public int GetSize()
    {
        return from.length + to.length;
    }

    public byte[] GetFrom()
    {
        return from;
    }

    public byte[] GetTo()
    {
        return to;
    }

    public void SetFrom(byte[] from)
    {
        this.from = super.SafeSetByteArray(this.from,from);
    }

    public void SetTo(byte[] to)
    {
        this.to = super.SafeSetByteArray(this.to,to);
    }
}
