package Message.offline.entity;

import Message.CodecUtil;
import Message.EtcsInfo;
import Message.constant.Common.*;
import Message.constant.Offline.*;
import java.io.*;

public class ReplaceEtcsEntities extends CodecUtil {
    private EtcsInfo KmEtcsIdExp = new EtcsInfo();
    private byte[] serialNumber = new byte[OFFLINE_KEY_MESSAGE_SIZE.SERIAL_SIZE];
    private byte[] peerNum = new byte[OFFLINE_KEY_MESSAGE_SIZE.PEER_NUM_SIZE];
    private EtcsInfo[] EtcsIdExpPeer = null;
    private byte[] cbcMac = new byte[COMMON_SIZE.CBC_MAC_SIZE];

    /**
     * 기본 생성자
     * @param KmEtcsIdExp ETCS ID type and ETCS ID of the KMC that issued the authentication key to which
     * @param serialNumber Unique serial number of the authentication key to which entities are to be added (together with the KM-ETCS-ID-TYPE, this identifies the triple-key unambiguously)
     * @param peerNum Number m of peer ETCS entities. PEER-NUM shall be greater or equal to ‘1’
     * @param EtcsIdExpPeer ETCS ID TYPE and ETCS ID of peer ETCS entities (i=1 to m)
     * @param cbcMac The CBC-MAC shall be calculated over the complete message from octet 1 up to but excluding the CBC-MAC field using transport key KTRANS1
     */
    public ReplaceEtcsEntities(EtcsInfo KmEtcsIdExp, byte[] serialNumber, byte[] peerNum, EtcsInfo[] EtcsIdExpPeer, byte[] cbcMac)
    {
        SetKmEtcsIdExp(KmEtcsIdExp);
        SetSerialNumber(serialNumber);
        SetPeerNum(peerNum);
        SetEtcsIdExpPeer(EtcsIdExpPeer);
        SetCbcMac(cbcMac);
    }

    public ReplaceEtcsEntities(){}

    /**
     * * Initialize the class KEY_MESSAGE_DELETE_STRUCT
     * @param bReplaceEtcsEntitiesMessage the byte array containing the data to initialize the fields
     */
    public ReplaceEtcsEntities(byte[] bReplaceEtcsEntitiesMessage) throws IllegalArgumentException
    {
        if(DecodeMessage(bReplaceEtcsEntitiesMessage) != OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_SUCCESSFULLY_PROCESSED)
        {
            throw new IllegalArgumentException(EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
        }
    }

    /**
     * * Initialize the class KEY_MESSAGE_DELETE_STRUCT
     * @param bReplaceEtcsEntitiesMessage the byte array containing the data to initialize the fields
     * @return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE [0,12,13]
     */
    public int DecodeMessage(byte[] bReplaceEtcsEntitiesMessage)
    {
        try
        {
            return DeserializeFromBytes(bReplaceEtcsEntitiesMessage);
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
     * @return 구조체의 크기 반환
     */
    public int GetSize()
    {
        return this.KmEtcsIdExp.GetSize() + this.serialNumber.length + this.peerNum.length +
                (this.EtcsIdExpPeer != null ? this.EtcsIdExpPeer.length * this.EtcsIdExpPeer[0].GetSize(): COMMON_SIZE.EMPTY )  /* ETCS NULL CHECK */
                + this.cbcMac.length;
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
                byte[] bEtcsTemp = new byte[COMMON_SIZE.ETCS_STRUCT_SIZE];
                dis.readFully(bEtcsTemp);
                this.KmEtcsIdExp.DecodeMessage(bEtcsTemp);

                dis.readFully(this.serialNumber);
                dis.readFully(this.peerNum);

                int nPeerToInt = super.ConvertByteArrayToInt(this.peerNum);
                this.EtcsIdExpPeer = new EtcsInfo[nPeerToInt];
                for (int idx = 0; idx < nPeerToInt; idx++) {
                    byte[] bEtcsId = new byte[COMMON_SIZE.ETCS_STRUCT_SIZE];
                    dis.readFully(bEtcsId);
                    this.EtcsIdExpPeer[idx] = new EtcsInfo();
                }

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
        if(this.EtcsIdExpPeer.length != super.ConvertByteArrayToInt(this.peerNum) )
        {
            throw new IOException("peer etcs object size error");
        }

        byte[] bEtcsObjectByteArray = new byte[COMMON_SIZE.EMPTY];

        for(EtcsInfo object : this.EtcsIdExpPeer)
        {
            bEtcsObjectByteArray = super.AddPacket(bEtcsObjectByteArray, object.EncodeObject());
        }

        return super.SerializeMultipleByteArrays(
                this.KmEtcsIdExp.EncodeObject(),
                this.serialNumber,
                this.peerNum,
                bEtcsObjectByteArray,
                this.cbcMac
        );
    }

    public EtcsInfo GetKmEtcsIdExp()
    {
        return this.KmEtcsIdExp;
    }

    public void SetKmEtcsIdExp(EtcsInfo KmEtcsIdExp)
    {
        this.KmEtcsIdExp = KmEtcsIdExp;
    }

    public byte[] GetSerialNumber()
    {
        return this.serialNumber;
    }

    public void SetSerialNumber(byte[] serialNumber)
    {
        this.serialNumber = super.SafeSetByteArray(this.serialNumber,serialNumber);;
    }

    public byte[] GetPeerNum()
    {
        return this.peerNum;
    }

    public void SetPeerNum(byte[] peer_num)
    {
        this.peerNum = super.SafeSetByteArray(this.peerNum,peer_num);
    }

    public EtcsInfo[] GetEtcsIdExpPeer()
    {
        return this.EtcsIdExpPeer;
    }

    public void SetEtcsIdExpPeer(EtcsInfo[] EtcsIdExpPeer)
    {
        this.EtcsIdExpPeer = EtcsIdExpPeer;
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
