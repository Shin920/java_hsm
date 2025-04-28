package Message.offline.kmc;

import Message.CodecUtil;
import Message.constant.Common;
import Message.EtcsInfo;
import Message.constant.Offline.*;
import java.io.*;

/**
 *  038 key_offline[kmc<->kmc] KEY_MESSAGE : CONF_KMAC_DELETION(0b00000111)
 * @field km_msg -> Confirmation of KMAC deletion message.
 * @field subtype -> The subtype of the confirmation message.
 * @field ob_etcs_id -> The ETCS-ID expanded of the On-Board ERTMS Identity. It is unique per On-Board.
 * @field tr_struct -> The Trackside struct
 * @field km_etcs_id1 -> Issuer KM ETCS ID
 * @field km_etcs_id2 -> Target KM ETCS ID
 * @field issue_date -> The issue date of the key management message.
 * @field tnum -> This Transaction Number identifies unambiguously the negative acknowledgment and is equal to the TNUM received in the aborted KMAC message
 * @field cbc_mac -> Message authentication code for the message.
 */
public class ConfKmacDeletion extends CodecUtil
{
    private final byte kmMessage = OFFLINE_KM_MESSAGE.CONF_KMAC_DELETION;
    private byte subType;
    private byte[] obEtcsId = new byte[KM_MESSAGE_SIZE.ID_SIZE];
    private TracksidePeer TracksidePeer = new TracksidePeer();
    private EtcsInfo KmEtcsIdIssuer = new EtcsInfo();
    private EtcsInfo KmEtcsIdTarget = new EtcsInfo();
    private byte[] issueDate = new byte[KM_MESSAGE_SIZE.ISSUE_DATA_SIZE];
    private byte tNum;
    private byte[] cbcMac = new byte[Common.COMMON_SIZE.CBC_MAC_SIZE];

    public ConfKmacDeletion(){}

    /**
     * 기본 생성자
     * @param subType The subtype of the confirmation message.
     * @param obEtcsId The ETCS-ID expanded of the On-Board ERTMS Identity. It is unique per On-Board.
     * @param tracksidePeer The Trackside struct
     * @param KmEtcsIdIssuer Issuer KM ETCS ID
     * @param KmEtcsIdTarget Target KM ETCS ID
     * @param issueDate The issue date of the key management message
     * @param tNum This Transaction Number identifies unambiguously the negative acknowledgment and is equal to the TNUM received in the aborted KMAC message
     * @param cbcMac Message authentication code for the message.
     */
    public ConfKmacDeletion(byte subType, byte[] obEtcsId, TracksidePeer tracksidePeer, EtcsInfo KmEtcsIdIssuer, EtcsInfo KmEtcsIdTarget, byte[] issueDate, byte tNum, byte[] cbcMac)
    {
        SetSubType(subType);
        SetObEtcsId(obEtcsId);
        SetTracksidePeer(tracksidePeer);
        SetKmEtcsIdIssuer(KmEtcsIdIssuer);
        SetKmEtcsIdTarget(KmEtcsIdTarget);
        SetIssueDate(issueDate);
        SetTNum(tNum);
        SetCbcMac(cbcMac);
    }

    /**
     * Constructs a CONF_KMAC_DELETION instance from the given byte array buffer.
     * This constructor initializes the fields of the class based on the buffer contents.
     *
     * @param byteArrayInputStream the byte array containing the data to initialize the fields
     */
    public ConfKmacDeletion(byte[] byteArrayInputStream) throws IllegalArgumentException
    {
        if(!DecodeMessage(byteArrayInputStream))
        {
            throw new IllegalArgumentException(Common.EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
        }
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
     * @return 클래스의 필드 인스턴스들을 바이트 배열로 직렬화하여 반환
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


    /**
     * Constructs a KMAC_NEGACK instance from the given byte array buffer.
     * This constructor initializes the fields of the class based on the buffer contents.
     *
     * @param kmacDeletion Object for initializing default values in fields
     */
    public ConfKmacDeletion(KmacDeletion kmacDeletion)
    {
        IncorporateKmacDeletion(kmacDeletion);
    }

    private void DeserializeFromBytes(byte[] byteArrayInputStream) throws Exception
    {
        if (byteArrayInputStream == null || byteArrayInputStream.length == 0)
        {
            throw new IllegalArgumentException("Input stream is null or empty");
        }

        try (ByteArrayInputStream bais = new ByteArrayInputStream(byteArrayInputStream);
             DataInputStream dis = new DataInputStream(bais))
        {
            try
            { /* EOF Check */
                /* Read and ignore km_msg, because it's a constant */
                byte bReadKmMsg = dis.readByte();
                if (bReadKmMsg != this.kmMessage)
                {
                    throw new IOException("Invalid km_msg value.");
                }

                /* Read the rest of the fields */
                this.subType = dis.readByte();
                dis.readFully(this.obEtcsId);

                byte bTrQuant = dis.readByte();
                byte[] bTrEtcsId = new byte[bTrQuant * KM_MESSAGE_SIZE.ETCS_STRUCT_SIZE];
                dis.readFully(bTrEtcsId);

                /* Combine tr_quant and tr_etcs_id into one array */
                byte[] bCombinedArray = new byte[1 + bTrEtcsId.length];
                bCombinedArray[0] = bTrQuant;
                System.arraycopy(bTrEtcsId, 0, bCombinedArray, 1, bTrEtcsId.length);
                this.TracksidePeer = new TracksidePeer(bCombinedArray);


                byte[] bTempEtcsArray = new byte[KM_MESSAGE_SIZE.ETCS_STRUCT_SIZE];
                dis.readFully(bTempEtcsArray);
                this.KmEtcsIdIssuer.DecodeMessage(bTempEtcsArray);
                dis.readFully(bTempEtcsArray);
                this.KmEtcsIdTarget.DecodeMessage(bTempEtcsArray);

                dis.readFully(this.issueDate);
                this.tNum = dis.readByte();
                dis.readFully(this.cbcMac);

                /* 스트림에 남은 바이트가 있는지 확인 */
                if (dis.available() > Common.COMMON_SIZE.EMPTY)
                {
                    throw new IllegalArgumentException(Common.EXCEPTION_STRING.EXCEPTION_EXTRA_BYTE);
                }
            }
            catch (EOFException e)
            {
                /* 익셉션 발생 이유 설명 및 스택 트레이스 복사 */
                EOFException exception = new EOFException(Common.EXCEPTION_STRING.EXCEPTION_DESERIALIZE_FAIL);
                exception.setStackTrace(e.getStackTrace());
                throw exception;
            }
        }
    }

    /* Byte-serialize field instance values */
    private byte[] SerializeToBytes() throws IOException
    {
        return super.SerializeMultipleByteArrays(
                new byte[]{kmMessage, subType},
                this.obEtcsId,
                this.TracksidePeer.EncodeObject(),
                this.KmEtcsIdIssuer.EncodeObject(),
                this.KmEtcsIdTarget.EncodeObject(),
                this.issueDate,
                new byte[]{tNum},
                this.cbcMac);
    }

    /***
     * @return 구조체의 크기를 반환
     */
    public int GetSize()
    {
        return KM_MESSAGE_SIZE.KM_MESSAGE_SIZE + KM_MESSAGE_SIZE.SUBTYPE_SIZE + this.obEtcsId.length + this.TracksidePeer.GetSize() +
                this.KmEtcsIdIssuer.GetSize() + this.KmEtcsIdTarget.GetSize() + this.issueDate.length + KM_MESSAGE_SIZE.TNUM_SIZE + this.cbcMac.length;
    }

    /***
     * 바이트 배열을 받아 구조체로 병합
     * @param bConfKmacDeletionMessage 구조로 복사할 바이트 배열
     * @return 성공여부 반환
     */
    private boolean IncorporateMsgFromBuffer(byte[] bConfKmacDeletionMessage){
        try {
            DeserializeFromBytes(bConfKmacDeletionMessage);
            switch (bConfKmacDeletionMessage[0])
            {
                case OFFLINE_KM_MESSAGE.CONF_KMAC_DELETION ->
                {
                    DeserializeFromBytes(bConfKmacDeletionMessage);
                }
                case OFFLINE_KM_MESSAGE.KMAC_DELETION ->
                {
                    KmacDeletion msg = new KmacDeletion(bConfKmacDeletionMessage);
                    IncorporateKmacDeletion(msg);
                }
                default ->
                {
                    throw new IllegalStateException("Unexpected value: " + bConfKmacDeletionMessage[0]);
                }
            }
            return true;
        }
        catch (Exception e )
        {
            super.IsExceptionPrintingAndWriteLog(e);
        }

        return false;
    }

    /**
     * Incorporates KMAC_UPDATE fields and methods into CONF_KMAC_DELETION.
     * Ensure no essential inheritance and fields are missing.
     *
     * @param kmacDeletion KMAC_UPDATE instance to incorporate
     */
    public void IncorporateKmacDeletion(KmacDeletion kmacDeletion)
    {
        this.obEtcsId = kmacDeletion.GetObEtcsId();
        this.TracksidePeer = kmacDeletion.GetTracksidePeer();
        this.KmEtcsIdIssuer = kmacDeletion.GetKmEtcsIdIssuer();
        this.KmEtcsIdTarget = kmacDeletion.GetKmEtcsIdTarget();
        this.issueDate = kmacDeletion.GetIssueDate();
        this.tNum = kmacDeletion.GetTNum();
    }

    public byte GetKmMessage()
    {
        return kmMessage;
    }

    public byte GetSubType()
    {
        return subType;
    }

    public void SetSubType(byte subType)
    {
        try
        {
            switch (subType)
            {
                case KM_SUBTYPE.DELETION_SUBTYPE_DELETE_NOTIFICATION,
                        KM_SUBTYPE.DELETION_SUBTYPE_DELETE_REQUEST  ->
                {
                    /* 서브타입 아닐 때 체크 */
                }
                default -> throw new IOException("sub type value Error expected value : (0000 0010 or 0000 0100)");
            }
        }
        catch (IOException e )
        {
            super.IsExceptionPrintingAndWriteLog(e);
        }
        finally /* 예외 발생 여부와 상관없이 subtype 값을 설정 */
        {
            this.subType = subType;
        }
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
        return TracksidePeer;
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
        this.cbcMac = cbcMac;
    }
}