package communication.packet;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.LinkedList;
import java.util.Queue;

import static communication.CONFIG.*;

public class HsmPacket extends PacketUtil
{
    private byte headerType;
    private byte headerEvent;
    private byte[] bodyData; /* TODO : 위의 헤더 타입과 이벤트를 가지고 바디 데이터를 파싱해야 함 */


    public HsmPacket(){}

    public HsmPacket(byte[] bHsmPacketBuffer) throws IllegalArgumentException
    {
        if( !DecodeMessage(bHsmPacketBuffer) )
        {
            throw new IllegalArgumentException("Buffer error");
        }
    }

    public HsmPacket(byte headerType, byte headerEvent, byte[] bodyData)
    {
        this.headerType = headerType;
        this.headerEvent = headerEvent;
        this.bodyData = bodyData;
    }

    /**
     * 데이터 파싱
     * @param bHsmPacketBuffer 파싱을 진행할 패킷 데이터
     * @return 성공여부
     */
    public boolean DecodeMessage(byte[] bHsmPacketBuffer)
    {
        try
        {
            return DeserializeFromBytes(bHsmPacketBuffer);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return false;
        }
    }

    private boolean DeserializeFromBytes(byte[] byteArrayInputStream) throws Exception
    {
        if (byteArrayInputStream == null)
        {
            throw new IllegalArgumentException("buffer size is null");
        }

        try (ByteArrayInputStream bais = new ByteArrayInputStream(byteArrayInputStream);
             DataInputStream dis = new DataInputStream(bais))
        {
            this.headerType = dis.readByte();
            this.headerEvent = dis.readByte();

            this.bodyData = new byte[ dis.available() ]; /* 헤더를 구성하고 남은 바이트는 전부 바디 데이터로 밀어넣음*/
            dis.readFully(this.bodyData);
        }

        return true;
    }

    /**
     * 현재 클래스에 구성된 필드 인스턴스 직렬화
     * @return serialized buffer
     */
    public byte[] EncodeObject()
    {
        try
        {
            return super.SerializeMultipleByteArrays(
                    new byte[] {this.headerType,this.headerEvent},
                    this.bodyData );
        }
        catch (IOException e)
        {
            e.printStackTrace();
            return super.MakeErrorPacket(GetSize());
        }
    }

    public boolean isCheckHeader()
    {
        return isCheckHeaderType() && isCheckHeaderEvent(); /* 타입과 이벤트가 전부 true 반환되어야 정상 헤더  */
    }

    public boolean isCheckHeaderType()
    {
        return switch(this.headerType)
        {
            case HSM_PACKET.HEADER_TYPE_HSM,
                 HSM_PACKET.HEADER_TYPE_DIST_APP,
                 HSM_PACKET.HEADER_TYPE_WEB_APP -> true;
            default -> false;
        };
    }

    /* TODO : 타입 정해지면 체크해서 false 조건도 넣어줘야 함 */
    public boolean isCheckHeaderEvent()
    {
        return true;
    }

    public int GetSize()
    {
        return 1 + 1 + this.bodyData.length;
    }

    public byte getHeaderType()
    {
        return headerType;
    }

    public void setHeaderType(byte headerType)
    {
        this.headerType = headerType;
    }

    public byte getHeaderEvent()
    {
        return headerEvent;
    }

    public void setHeaderEvent(byte headerEvent)
    {
        this.headerEvent = headerEvent;
    }

    public byte[] getBodyData()
    {
        return bodyData;
    }

    public void setBodyData(byte[] bodyData)
    {
        this.bodyData = bodyData;
    }
}
