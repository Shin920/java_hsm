package Message.offline.kmc;

import Message.CodecUtil;
import Message.EtcsInfo;
import Message.constant.Common.*;
import Message.constant.Offline.*;
import java.io.*;

public class TracksidePeer extends CodecUtil
{
    private byte tracksideQuant;
    private EtcsInfo[] EtcsIdExpTrackside = null;

    /**
     * 기본 생성자
     * @param tracksideQuant etcs_id 개수
     * @param EtcsIdExpTrackside 트랙사이드 ETCS ID
     */
    public TracksidePeer(byte tracksideQuant, EtcsInfo[] EtcsIdExpTrackside)
    {
        SetTracksideQuant(tracksideQuant);
        SetEtcsIdExpTrackside(EtcsIdExpTrackside);
    }

    public TracksidePeer(){}

    public TracksidePeer(byte[] bTracksidePeerMessage) throws  IllegalArgumentException
    {
        if(!DecodeMessage(bTracksidePeerMessage))
        {
            throw new IllegalArgumentException(EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
        }
    }

    public boolean DecodeMessage(byte[] bTracksidePeerMessage)
    {
        try
        {
            DeserializeFromBytes(bTracksidePeerMessage);
            return true;
        }
        catch (Exception e)
        {
            super.IsExceptionPrintingAndWriteLog(e);
            return false;
        }
    }

    /**
     * KM_TRACKSIDE_STRUCT Class Returns a serialized value.
     * Check whether the key_type value is the correct value.
     * @return serialize to KM_TRACKSIDE_STRUCT values
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
     * @return 구조체의 크기 반환
     */
    public int GetSize()
    {
        return KM_MESSAGE_SIZE.TR_QUANT_SIZE +
                (this.EtcsIdExpTrackside != null ? this.EtcsIdExpTrackside.length * KM_MESSAGE_SIZE.ETCS_STRUCT_SIZE : COMMON_SIZE.EMPTY) ;
    }

    public void DeserializeFromBytes(byte[] byteArrayInputStream) throws Exception
    {
        if (byteArrayInputStream == null || byteArrayInputStream.length == COMMON_SIZE.EMPTY)
        {
            throw new IllegalArgumentException("Input stream is null or empty");
        }

        try (ByteArrayInputStream bais = new ByteArrayInputStream(byteArrayInputStream);
             DataInputStream dis = new DataInputStream(bais))
        {
            try
            { /* EOF check */
                this.tracksideQuant = dis.readByte();
                if (byteArrayInputStream.length != (this.tracksideQuant * KM_MESSAGE_SIZE.ETCS_STRUCT_SIZE) + KM_MESSAGE_SIZE.TR_QUANT_SIZE)
                {
                    throw new IllegalArgumentException("Buffer Size Error");
                }

                this.EtcsIdExpTrackside = new EtcsInfo[this.tracksideQuant];

                for (int idx = KM_MESSAGE_IDX.FIST_IDX; idx < this.EtcsIdExpTrackside.length; idx++) {
                    byte[] bTempEtcsId = new byte[KM_MESSAGE_SIZE.ETCS_STRUCT_SIZE];
                    dis.readFully(bTempEtcsId);
                    this.EtcsIdExpTrackside[idx] = new EtcsInfo(bTempEtcsId);
                }


                /* 스트림에 남은 바이트가 있는지 확인 */
                if (dis.available() > COMMON_SIZE.EMPTY)
                {
                    throw new IllegalArgumentException(EXCEPTION_STRING.EXCEPTION_EXTRA_BYTE);
                }
            }
            catch (EOFException e)
            {
                /* 익셉션 발생 이유 설명 및 스택 트레이스 복사 */
                EOFException exception = new EOFException(EXCEPTION_STRING.EXCEPTION_DESERIALIZE_FAIL);
                exception.setStackTrace(e.getStackTrace());
                throw exception;
            }
        }
    }

    /* Byte-serialize field instance values */
    private byte[] SerializeToBytes() throws IOException
    {
        byte[] bSerializedMsg = new byte[COMMON_SIZE.EMPTY];

        for(EtcsInfo obEtcs : this.EtcsIdExpTrackside)
        {
            bSerializedMsg = super.AddPacket(bSerializedMsg,obEtcs.EncodeObject());
        }

        return super.SerializeMultipleByteArrays(new byte[]{this.tracksideQuant}, bSerializedMsg);
    }

    public byte GetTracksideQuant()
    {
        return this.tracksideQuant;
    }

    public void SetTracksideQuant(byte tr_quant)
    {
        this.tracksideQuant = tr_quant;
        this.EtcsIdExpTrackside = new EtcsInfo[this.tracksideQuant];

        for(int idx = KM_MESSAGE_IDX.FIST_IDX; idx < this.EtcsIdExpTrackside.length; idx ++)
        {
            this.EtcsIdExpTrackside[idx] = new EtcsInfo();
        }
    }

    public EtcsInfo[] GetEtcsIdExpTrackside()
    {
        return this.EtcsIdExpTrackside;
    }

    public void SetEtcsIdExpTrackside(EtcsInfo[] EtcsIdExpTrackside)
    {
        this.EtcsIdExpTrackside = EtcsIdExpTrackside;
    }
}
