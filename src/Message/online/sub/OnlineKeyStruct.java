package Message.online.sub;

import Message.CodecUtil;
import Message.constant.Common.*;
import Message.constant.Online.*;
import Message.EtcsInfo;
import Message.ValidPeriod;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;

public class OnlineKeyStruct extends CodecUtil
{
    private byte length;
    private IdentifierKey Identifier = new IdentifierKey();
    private EtcsInfo EtcsIdExp = new EtcsInfo();
    private byte[] kMac = new byte[ONLINE_KEY_SIZE.KMAC_SIZE];
    private byte[] peerNum = new byte[ONLINE_KEY_SIZE.PEER_NUM_SIZE];
    private EtcsInfo[] EtcsIdPeer = null;
    private ValidPeriod ValidPeriod = new ValidPeriod();

    public OnlineKeyStruct(){}

    /**
     * 기본 생성자
     * @param length The key length in bytes (KMAC)
     * @param Identifier Structure that uniquely identifies a key
     * @param EtcsIdExp The expanded ETCS-ID of the recipient KMAC entity
     * @param kMac The authentication key
     * @param peerNum The number of peer entities following this field. At least one peer entity shall be specified in K-STRUCT
     * @param EtcsIdPeer List of KMAC entities linked to this key.
     * @param ValidPeriod Validity period
     */
    public OnlineKeyStruct(byte length, IdentifierKey Identifier, EtcsInfo EtcsIdExp, byte[] kMac, byte[] peerNum, byte[] EtcsIdPeer, ValidPeriod ValidPeriod)
    {
        this.length = length;
        this.Identifier = Identifier;
        this.EtcsIdExp = EtcsIdExp;
        this.kMac = kMac;
        this.peerNum = peerNum;
        this.ValidPeriod = ValidPeriod;
    }

    /**
     * 바이트 배열을 통해 구조체 초기화
     * @param bStructMessage 메시지 패킷
     * @throws IllegalArgumentException 발생 가능한 예외처리
     */
    public OnlineKeyStruct(byte[] bStructMessage) throws IllegalArgumentException
    {
        if(DecodeMessage(bStructMessage) != ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_REQUEST_SUCCESSFULLY_PROCESSED)
        {
            throw new IllegalArgumentException(EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
        }
    }

    /**
     * 바이트 배열을 통해 구조체 초기화
     * @param bStructMessage 메시지 패킷
     */
    public int DecodeMessage(byte[] bStructMessage)
    {
        try
        {
            return DeserializeFromBytes(bStructMessage);
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
    public byte[] EncodeObject(){
        try
        {
            byte[] bPeerPacket = new byte[COMMON_SIZE.EMPTY];
            for(EtcsInfo EtcsObject : this.EtcsIdPeer)
            {
                bPeerPacket = super.AddPacket(bPeerPacket,EtcsObject.EncodeObject());
            }

            return super.SerializeMultipleByteArrays(
                    new byte[]{length},
                    this.Identifier.EncodeObject(),
                    this.EtcsIdExp.EncodeObject(),
                    this.kMac,
                    this.peerNum,
                    bPeerPacket,
                    this.ValidPeriod.EncodeObject()
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
            try /* EOF Check */
            {
                this.length = dis.readByte();
                if(this.length != ONLINE_KEY_SIZE.KMAC_SIZE)
                {
                    IsExceptionPrintingAndWriteLog( new IllegalArgumentException("[OnlineKeyStruct] length value Error"));
                    return ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_FORMAT_ERROR;
                }

                /* Identifier */
                byte[] bIdentifierBuffer = new byte[ONLINE_KEY_SIZE.IDENTIFIER_STRUCT_SIZE];
                dis.readFully(bIdentifierBuffer);
                this.Identifier.DecodeMessage(bIdentifierBuffer);

                /* ETCS */
                byte[] bEtcsId = new byte[COMMON_SIZE.ETCS_STRUCT_SIZE];
                dis.readFully(bEtcsId);
                this.EtcsIdExp.DecodeMessage(bEtcsId);

                dis.readFully(this.kMac);
                dis.readFully(this.peerNum);

                /* peer_id */
                int nPeerCnt = GetPeer_numToInt();
                if(!(nPeerCnt >= 1 && nPeerCnt <= 100))
                {
                    IsExceptionPrintingAndWriteLog( new IllegalArgumentException("[OnlineKeyStruct] peerNum value Error"));
                    return ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_FORMAT_ERROR;
                }

                EtcsIdPeer = new EtcsInfo[nPeerCnt];
                for (int idx = 0; idx < nPeerCnt; idx++)
                {
                    byte[] bPeerId = new byte[COMMON_SIZE.ETCS_STRUCT_SIZE];
                    dis.readFully(bPeerId);
                    EtcsIdPeer[idx] = new EtcsInfo(bPeerId);
                }

                /* Valid Period */
                byte[] bValidPeriod = new byte[COMMON_SIZE.VALID_PERIOD_STRUCT_SIZE];
                dis.readFully(bValidPeriod);
                this.ValidPeriod.DecodeMessage(bValidPeriod);

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
        if(this.EtcsIdPeer == null)
        {
            WriteErrorLog("peer_id is null");
            return super.ERROR_CODE;
        }
        return ONLINE_KEY_SIZE.LENGTH_FILED_SIZE + this.Identifier.GetSize() + this.EtcsIdExp.GetSize() + this.kMac.length +
                this.peerNum.length + (this.EtcsIdPeer.length * this.EtcsIdPeer[0].GetSize()) + this.ValidPeriod.GetSize();
    }

    public int GetPeer_numToInt()
    {
        /* convert byte array to integer */
        return ( this.peerNum[0] & 0xFF ) << 8 | ( this.peerNum[1] & 0xFF );
    }

    public byte GetLength()
    {
        return this.length;
    }

    public void SetLength(byte length)
    {
        this.length = length;
    }

    public IdentifierKey GetIdentifier()
    {
        return this.Identifier;
    }

    public void SetIdentifier(IdentifierKey identifier)
    {
        this.Identifier = identifier;
    }

    public EtcsInfo GetEtcsIdExp()
    {
        return this.EtcsIdExp;
    }

    public void SetEtcsIdExp(EtcsInfo etcsIdExp)
    {
        this.EtcsIdExp = etcsIdExp;
    }

    public byte[] GetkMac()
    {
        return this.kMac;
    }

    public void SetkMac(byte[] kMac)
    {
        this.kMac = super.SafeSetByteArray(this.kMac,kMac);
    }

    public byte[] GetPeerNum()
    {
        return this.peerNum;
    }

    public void SetPeerNum(byte[] peerNum)
    {
        this.peerNum = peerNum;
    }

    public EtcsInfo[] GetEtcsIdPeer()
    {
        return this.EtcsIdPeer;
    }

    public void SetEtcsIdPeer(EtcsInfo[] etcsIdPeer)
    {
        this.EtcsIdPeer = etcsIdPeer;
    }

    public ValidPeriod GetValidPeriod()
    {
        return this.ValidPeriod;
    }

    public void SetValidPeriod(ValidPeriod validPeriod)
    {
        this.ValidPeriod = validPeriod;
    }




    public static void main(String[] args)
    {
        byte[] bOnlineKeySampleMessage =
                {
                        0x18, // LENGTH
                        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08, // IdentifierKey
                        0x09,0x0a,0x0b,0x0c, // etcs id
                        0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10, // kmac
                        0x00,0x02, // peerNum
                        0x11,0x11,0x11,0x11, // peer 1
                        0x12,0x12,0x12,0x12, // peer 2
                        0x13,0x13,0x13,0x13,0x14,0x14,0x14,0x14, // valid_period
                };
        try
        {
            OnlineKeyStruct k_struct = new OnlineKeyStruct(bOnlineKeySampleMessage);
            for(byte b : k_struct.EncodeObject())
            {
                System.out.printf("%02X ", b);
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }
}
