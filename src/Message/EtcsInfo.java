package Message;

import Message.constant.Common.*;
import java.io.IOException;
import java.util.Arrays;

/**
 * ETCS ID의 타입과 값을 저장하는 구조체 클래스
 * @field id_type -> ID의 타입
 * @field id -> ID값
 * */
public class EtcsInfo extends CodecUtil
{
    private byte etcsIdType;
    private byte[] etcsId = new byte[COMMON_SIZE.ETCS_ID_SIZE];

    /**
     * etcs 구조체 기본 생성자
     * @param EtcsIdType 타입
     * @param etcsId id value
     */
    public EtcsInfo(byte EtcsIdType, byte[] etcsId)
    {
        SetEtcsIdType(EtcsIdType);
        SetEtcsId(etcsId);
    }

    public EtcsInfo()
    {
        /* 기본 생성자 */
    }

    /**byteArray 로부터 구조체를 초기화하는 메서드
     *
     * @param bKeyEtcsMessage etcs 구조체 패킷
     */
    public EtcsInfo(byte[] bKeyEtcsMessage) throws IllegalArgumentException
    {

        if(!DecodeMessage(bKeyEtcsMessage))
        {
            throw new IllegalArgumentException(EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
        }
    }

    /**byteArray 로부터 구조체를 초기화하는 메서드
     *
     * @param bKeyEtcsMessage etcs 구조체 패킷
     */
    public boolean DecodeMessage(byte[] bKeyEtcsMessage)
    {
        if (bKeyEtcsMessage.length == COMMON_SIZE.ETCS_STRUCT_SIZE)
        {
            SetEtcsIdType(bKeyEtcsMessage[COMMON_SIZE.ETCS_MESSAGE_TYPE_IDX]);
            //this.etcsIdType = bKeyEtcsMessage[COMMON_SIZE.ETCS_MESSAGE_TYPE_IDX];
            System.arraycopy(bKeyEtcsMessage, 1, this.etcsId, 0, 3);
            return true;
        }
        else
        {
            this.etcsIdType = ERROR_BYTE;
            Arrays.fill(this.etcsId, ERROR_BYTE);
            IsExceptionPrintingAndWriteLog(new IllegalArgumentException("Byte array must be exactly 4 bytes long."));
            return false;
        }
    }

    public boolean CheckEtcsTypeValue(byte bEtcsType)
    {
        return switch(bEtcsType)
        {
            case ETCS_TYPE.RADIO_IN_FILL_UNIT,
                    ETCS_TYPE.RBC,
                    ETCS_TYPE.RESERVED_FOR_FIELD_ELEMENT,
                    ETCS_TYPE.RESERVED_FOR_BALISE,
                    ETCS_TYPE.KEY_MANAGEMENT_ENTITY,
                    ETCS_TYPE.INTERLOCKING_RELATED_ENTITY,
                    ETCS_TYPE.UNKNOWN -> true;
            default -> false;
        };
    }

    /**
     * struct to byte array
     * */
    public byte[] EncodeObject()
    {
        try
        {
            return super.SerializeMultipleByteArrays(new byte[]{etcsIdType}, etcsId);
        }
        catch (IOException e)
        {
            super.IsExceptionPrintingAndWriteLog(e);
            return super.MakeErrorPacket(GetSize());
        }
    }

    /**
     * 구조체의 크기를 반환
     * @return struct Size
     */
    public int GetSize()
    {
        return this.etcsId.length + COMMON_SIZE.ETCS_ID_TYPE_SIZE;
    }

    /* id 배열을 설정하는 메서드 */
    public void SetEtcsId(byte[] id)
    {
        this.etcsId = super.SafeSetByteArray(this.etcsId,id);
    }

    /** etcsIdType 을 설정하는 메서드 */
    public void SetEtcsIdType(byte etcsIdType)
    {
        this.etcsIdType = etcsIdType;
    }


    /** id_type 값을 반환하는 메서드 */
    public byte GetEtcsIdType()
    {
        return this.etcsIdType;
    }

    // id 배열을 반환하는 메서드
    public byte[] GetEtcsId()
    {
        return this.etcsId;
    }
}