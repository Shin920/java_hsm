package Message.offline.kmc;

import Message.CodecUtil;
import Message.EtcsInfo;
import Message.constant.Common.*;
import Message.constant.Offline.*;
import java.io.*;


/**
 *  038 key_offline[kmc<->kmc] KM_MESSAGE  : CONF_KMAC_EXCHANGE(0b00000101)
 * @field km_msg -> KMAC exchange confirmation message.
 * @field ob_etcs_id -> The ETCS-ID expanded of the On-Board ERTMS Identity. It is unique per On-Board.
 * @field tr_struct -> The Trackside struct
 * @field km_etcs_id1 -> Issuer KM ETCS ID
 * @field km_etcs_id2 -> Target KM ETCS ID
 * @field issue_date -> The issue date of the key management message.
 * @field tnum -> This Transaction Number identifies unambiguously the negative acknowledgment and is equal to the TNUM received in the aborted KMAC message
 * @field cbc_mac -> Message authentication code for the message.
 */
public class ConfKmacExchange extends CodecUtil
{
    private final byte kmMessage = OFFLINE_KM_MESSAGE.CONF_KMAC_EXCHANGE;
    private byte[] obEtcsId = new byte[KM_MESSAGE_SIZE.ID_SIZE];
    private TracksidePeer TracksidePeer = new TracksidePeer();
    private EtcsInfo KmEtcsIdIssuer = new EtcsInfo();
    private EtcsInfo KmEtcsIdTarget = new EtcsInfo();
    private byte[] issueDate = new byte[KM_MESSAGE_SIZE.ISSUE_DATA_SIZE];
    private byte tNum;
    private byte[] cbcMac = new byte[COMMON_SIZE.CBC_MAC_SIZE]; // cbc_mac 필드 추가

    /**
     * 기본 생성자
     * @param obEtcsId The ETCS-ID expanded of the On-Board ERTMS Identity. It is unique per On-Board.
     * @param tracksidePeer The Trackside struct
     * @param kmEtcsIdIssuer Issuer KM ETCS ID
     * @param kmsEtcsIdTarget Target KM ETCS ID
     * @param issueDate The issue date of the key management message.
     * @param tNum This Transaction Number identifies unambiguously the negative acknowledgment and is equal to the TNUM received in the aborted KMAC message
     * @param cbcMac Message authentication code for the message.
     */
    public ConfKmacExchange(byte[] obEtcsId, TracksidePeer tracksidePeer, EtcsInfo kmEtcsIdIssuer, EtcsInfo kmsEtcsIdTarget, byte[] issueDate, byte tNum, byte[] cbcMac)
    {
        SetObEtcsId(obEtcsId);
        SetTracksidePeer(tracksidePeer);
        SetKmEtcsIdIssuer(kmEtcsIdIssuer);
        SetKmEtcsIdTarget(kmsEtcsIdTarget);
        SetIssueDate(issueDate);
        SetTNum(tNum);
        SetCbcMac(cbcMac);
    }

    public ConfKmacExchange() {}

    /**
     * Constructs a CONF_KMAC_EXCHANGE instance from the given byte array buffer.
     * This constructor initializes the fields of the class based on the buffer contents.
     *
     * @param byteArrayInputStream the byte array containing the data to initialize the fields
     */
    public ConfKmacExchange(byte[] byteArrayInputStream) throws IllegalArgumentException
    {
        if(!DecodeMessage(byteArrayInputStream))
        {
            throw new IllegalArgumentException(EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
        }
    }

    /**
     * Constructs a KMAC_NEGACK instance from the given byte array buffer.
     * This constructor initializes the fields of the class based on the buffer contents.
     *
     * @param kmacExchange Object for initializing default values in fields
     */
    public ConfKmacExchange(KmacExchange kmacExchange)
    {
        IncorporateKmacExchange(kmacExchange);
    }


    public boolean DecodeMessage(byte[] byteArrayInputStream)
    {
        try
        {
            return IncorporateMsgFromBuffer(byteArrayInputStream);
        }
        catch (Exception e)
        {
            super.IsExceptionPrintingAndWriteLog(e);
            return false;
        }
    }

    /***
     *
     * @return 구조체의 모든 필드 인스턴스들의 값을 바이트 배열로 직렬화하여 반환
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
     * 바이트 배열을 받아 구조체로 병합
     * @param byteArrayInputStream 구조로 복사할 바이트 배열
     */
    private void DeserializeFromBytes(byte[] byteArrayInputStream) throws IOException
    {
        if (byteArrayInputStream == null || byteArrayInputStream.length == COMMON_SIZE.EMPTY)
        {
            throw new IllegalArgumentException("Input stream is null or empty");
        }

        try (ByteArrayInputStream bais = new ByteArrayInputStream(byteArrayInputStream);
             DataInputStream dis = new DataInputStream(bais))
        {

            try { /* EOF Check */
                /* Read and ignore km_msg, because it's a constant */
                byte bReadKmMsg = dis.readByte();
                if (bReadKmMsg != this.kmMessage) {
                    throw new IOException("Invalid km_msg value.");
                }

                /* Read the rest of the fields */
                dis.readFully(this.obEtcsId);

                byte bTruant = dis.readByte();
                byte[] bTrEtcsId = new byte[bTruant * KM_MESSAGE_SIZE.ETCS_STRUCT_SIZE];
                dis.readFully(bTrEtcsId);

                /* Combine tr_quant and tr_etcs_id into one array */
                byte[] bCombinedArray = new byte[KM_MESSAGE_SIZE.TR_QUANT_SIZE + bTrEtcsId.length];
                bCombinedArray[0] = bTruant;
                System.arraycopy(bTrEtcsId, 0, bCombinedArray, 1, bTrEtcsId.length);
                this.TracksidePeer = new TracksidePeer(bCombinedArray);

                byte[] bTempEtcsId = new byte[KM_MESSAGE_SIZE.ETCS_STRUCT_SIZE];
                dis.readFully(bTempEtcsId);
                this.KmEtcsIdIssuer.DecodeMessage(bTempEtcsId);
                dis.readFully(bTempEtcsId);
                this.KmEtcsIdTarget.DecodeMessage(bTempEtcsId);

                dis.readFully(this.issueDate);
                this.tNum = dis.readByte();

                /* Read cbc_mac field */
                dis.readFully(this.cbcMac);


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

    /**
     * Serializes the object fields into a byte array.
     *
     * @return the serialized byte array
     * @throws IOException if an I/O error occurs
     */
    private byte[] SerializeToBytes() throws IOException
    {
        return super.SerializeMultipleByteArrays(
                new byte[]{this.kmMessage},
                this.obEtcsId,
                this.TracksidePeer.EncodeObject(),
                this.KmEtcsIdIssuer.EncodeObject(),
                this.KmEtcsIdTarget.EncodeObject(),
                this.issueDate,
                new byte[]{this.tNum},
                this.cbcMac
        );
    }

    /***
     *
     * @return 구조체의 크기를 반환
     */
    public int GetSize()
    {
        return KM_MESSAGE_SIZE.KM_MESSAGE_SIZE + this.obEtcsId.length + this.TracksidePeer.GetSize() + this.KmEtcsIdIssuer.GetSize() +
                this.KmEtcsIdTarget.GetSize() + this.issueDate.length + KM_MESSAGE_SIZE.TNUM_SIZE + this.cbcMac.length;
    }

    /***
     * 바이트 배열의 타입을 검사하고 타입에 맞춰 병합 진행
     * @param bConfKmacExchange 구조체와 병합할 바이트 배열
     * @return 성공여부
     */
    private boolean IncorporateMsgFromBuffer(byte[] bConfKmacExchange)
    {
        try
        {
            /* 받은 메시지 타입을 검사*/
            switch (bConfKmacExchange[COMMON_SIZE.ETCS_MESSAGE_TYPE_IDX])
            {
                case OFFLINE_KM_MESSAGE.CONF_KMAC_EXCHANGE ->
                {
                    DeserializeFromBytes(bConfKmacExchange);
                }
                case OFFLINE_KM_MESSAGE.KMAC_EXCHANGE ->
                {
                    KmacExchange msg = new KmacExchange(bConfKmacExchange);
                    IncorporateKmacExchange(msg);
                }
                default -> throw new IllegalStateException("Unexpected value: " + bConfKmacExchange[0]);
            }
            return true;
        }
        catch (IOException e)
        {
            super.IsExceptionPrintingAndWriteLog(e);
            return false;
        }
    }

    /**
     * Incorporates KMAC_UPDATE fields and methods into CONF_KMAC_UPDATE.
     * Ensure no essential inheritance and fields are missing.
     *
     * @param kmacExchange KMAC_UPDATE instance to incorporate
     */
    private void IncorporateKmacExchange(KmacExchange kmacExchange)
    {
        this.obEtcsId = kmacExchange.GetObEtcsId();
        this.TracksidePeer = kmacExchange.GetTracksidePeer();
        this.KmEtcsIdIssuer = kmacExchange.GetKmEtcsIdIssuer();
        this.KmEtcsIdTarget = kmacExchange.GetKmEtcsIdTarget();
        this.issueDate = kmacExchange.GetIssueDate();
        this.tNum = kmacExchange.GetTNum();
    }

    public byte GetKmMessage()
    {
        return this.kmMessage;
    }

    public byte[] GetObEtcsId()
    {
        return this.obEtcsId;
    }

    public void SetObEtcsId(byte[] obEtcsId)
    {
        this.obEtcsId = super.SafeSetByteArray(this.obEtcsId,obEtcsId);
    }

    public TracksidePeer GetTracksidePeer()
    {
        return this.TracksidePeer;
    }

    public void SetTracksidePeer(TracksidePeer tracksidePeer)
    {
        this.TracksidePeer = tracksidePeer;
    }

    public EtcsInfo GetKmEtcsIdIssuer()
    {
        return this.KmEtcsIdIssuer;
    }

    public void SetKmEtcsIdIssuer(EtcsInfo kmEtcsIdIssuer)
    {
        this.KmEtcsIdIssuer = kmEtcsIdIssuer;
    }

    public EtcsInfo GetKmEtcsIdTarget()
    {
        return this.KmEtcsIdTarget;
    }

    public void SetKmEtcsIdTarget(EtcsInfo kmEtcsIdTarget)
    {
        this.KmEtcsIdTarget = kmEtcsIdTarget;
    }

    public byte[] GetIssueDate()
    {
        return this.issueDate;
    }

    public void SetIssueDate(byte[] issueDate)
    {
        this.issueDate = super.SafeSetByteArray(this.issueDate,issueDate);
    }

    public byte GetTNum()
    {
        return this.tNum;
    }

    public void SetTNum(byte tNum)
    {
        this.tNum = tNum;
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