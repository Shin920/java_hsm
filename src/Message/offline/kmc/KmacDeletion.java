package Message.offline.kmc;

import Message.CodecUtil;
import Message.constant.Common.*;
import Message.EtcsInfo;
import Message.constant.Offline.*;

import java.io.*;

/**
 *  038 key_offline[kmc<->kmc] KM_MESSAGE : KMAC_DELETION(0b00000110)
 * @field km_msg -> KMAC deletion message.
 * @field subtype -> The subtype of the deletion message.
 * @field tr_struct -> The Trackside struct
 * @field KmEtcsIdIssuer -> Issuer KM ETCS ID
 * @field KmEtcsIdTarget -> Target KM ETCS ID
 * @field issue_date -> The issue date of the key management message.
 * @field eff_date -> The effective date of the deletion.
 * @field tnum -> This Transaction Number identifies unambiguously the negative acknowledgment and is equal to the TNUM received in the aborted KMAC message
 * @field snum -> Serial number of the message.
 * @field reason -> The reason for the deletion.
 * @field cbc_mac -> Message authentication code for the message.
 */
public class KmacDeletion extends CodecUtil
{
    private final byte kmMessage = OFFLINE_KM_MESSAGE.KMAC_DELETION;
    private byte subType;
    private byte[] obEtcsId = new byte[KM_MESSAGE_SIZE.ID_SIZE];
    private TracksidePeer TracksidePeer = new TracksidePeer();
    private EtcsInfo KmEtcsIdIssuer = new EtcsInfo();
    private EtcsInfo KmEtcsIdTarget = new EtcsInfo();
    private byte[] issueDate = new byte[KM_MESSAGE_SIZE.ISSUE_DATA_SIZE];
    private byte[] effDate = new byte[KM_MESSAGE_SIZE.EFF_DATE_SIZE];
    private byte tNum;
    private byte[] sNum = new byte[KM_MESSAGE_SIZE.SNUM_SIZE];
    private byte reason;
    private byte[] cbcMac = new byte[COMMON_SIZE.CBC_MAC_SIZE];

    public KmacDeletion() {}

    /**
     * 기본 생성자
     * @param subType The subtype of the deletion message.
     * @param obEtcsId The ETCS-ID expanded of the On-Board ERTMS Identity. It is unique per On-Board.
     * @param TracksidePeer The Trackside struct
     * @param KmEtcsIdIssuer Issuer KM ETCS ID
     * @param KmEtcsIdTarget Target KM ETCS ID
     * @param issueDate The issue date of the key management message.
     * @param effDate The effective date of the deletion.
     * @param tNum This Transaction Number identifies unambiguously the negative acknowledgment and is equal to the TNUM received in the aborted KMAC message
     * @param sNum Serial number of the message.
     * @param reason The reason for the deletion.
     * @param cbcMac Message authentication code for the message.
     */
    public KmacDeletion(byte subType, byte[] obEtcsId, TracksidePeer TracksidePeer, EtcsInfo KmEtcsIdIssuer, EtcsInfo KmEtcsIdTarget, byte[] issueDate, byte[] effDate, byte tNum, byte[] sNum, byte reason, byte[] cbcMac)
    {
        SetSubType(subType);
        SetObEtcsId(obEtcsId);
        SetTracksidePeer(TracksidePeer);
        SetKmEtcsIdIssuer(KmEtcsIdIssuer);
        SetKmEtcsIdTarget(KmEtcsIdTarget);
        SetIssueDate(issueDate);
        SetEffDate(effDate);
        SetTNum(tNum);
        SetSNum(sNum);
        SetReason(reason);
        SetCbcMac(cbcMac);
    }

    /**
     * Constructs a KMAC_DELETION instance from the given byte array buffer.
     * This constructor initializes the fields of the class based on the buffer contents.
     *
     * @param byteArrayInputStream the byte array containing the data to initialize the fields
     */
    public KmacDeletion(byte[] byteArrayInputStream) throws IllegalArgumentException
    {
        if (!DecodeMessage(byteArrayInputStream))
        {
            throw new IllegalArgumentException(EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);

        }
    }

    public boolean DecodeMessage(byte[] byteArrayInputStream)
    {
        try
        {
            DeserializeFromBytes(byteArrayInputStream);
            return true;
        }
        catch (Exception e)
        {
            super.IsExceptionPrintingAndWriteLog(e);
            return false;
        }
    }

    /***
     *
     * @return 필드 인스턴스들의 값을 바이트 배열로 직렬화하여 반환
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
            {
                /* Read and ignore km_msg, because it's a constant */
                byte bReadKmMsg = dis.readByte();
                if (bReadKmMsg != this.kmMessage) {
                    throw new IOException("Invalid km_msg value.");
                }

                /* Read the rest of the fields */
                this.subType = dis.readByte();
                dis.readFully(this.obEtcsId);

                byte bTrQuant = dis.readByte();
                byte[] tr_etcs_id = new byte[bTrQuant * KM_MESSAGE_SIZE.ETCS_STRUCT_SIZE];
                dis.readFully(tr_etcs_id);

                /* Combine tr_quant and tr_etcs_id into one array */
                byte[] bCombinedArray = new byte[KM_MESSAGE_SIZE.TR_QUANT_SIZE + tr_etcs_id.length];
                bCombinedArray[KM_MESSAGE_IDX.TR_QUANT_IDX] = bTrQuant;
                System.arraycopy(tr_etcs_id, 0, bCombinedArray, 1, tr_etcs_id.length);
                this.TracksidePeer = new TracksidePeer(bCombinedArray);


                byte[] bTempEtcsId = new byte[KM_MESSAGE_SIZE.ETCS_STRUCT_SIZE];
                dis.readFully(bTempEtcsId);
                this.KmEtcsIdIssuer.DecodeMessage(bTempEtcsId);
                dis.readFully(bTempEtcsId);
                this.KmEtcsIdTarget.DecodeMessage(bTempEtcsId);

                dis.readFully(issueDate);
                dis.readFully(this.effDate);
                this.tNum = dis.readByte();
                dis.readFully(this.sNum);
                this.reason = dis.readByte();
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
                this.effDate,
                new byte[]{tNum},
                this.sNum,
                new byte[]{reason},
                this.cbcMac);
    }

    /***
     *
     * @return 구조체의 크기 반환
     */
    public int GetSize()
    {
        return KM_MESSAGE_SIZE.KM_MESSAGE_SIZE + KM_MESSAGE_SIZE.SUBTYPE_SIZE + this.obEtcsId.length + this.TracksidePeer.GetSize() +
                this.KmEtcsIdIssuer.GetSize() + this.KmEtcsIdTarget.GetSize() + this.issueDate.length + this.effDate.length + KM_MESSAGE_SIZE.TNUM_SIZE +
                this.sNum.length + KM_MESSAGE_SIZE.REASON_SIZE + this.cbcMac.length;
    }

    /***
     *
     * @return Reason Code parsing value
     */
    public String GetReasonCodeToString()
    {
        return GetReasonCodeToString(this.reason);
    }

    /**
     * Returns the reason code of a byte array as a string
     * @param bReasonCode Reason code in byte array * available values(0b00000010,0b00000100)
     * */
    public String GetReasonCodeToString(byte bReasonCode)
    {
        switch (bReasonCode)
        {
            case KM_REASON.DELETION_KMAC_CORRUPTION ->
            {
                return "Deletion request";
            }
            case KM_REASON.DELETION_TERMINATION_OF_SERVICE ->
            {
                return "Deletion notification";
            }
            default ->
            {
                return "Unknown reason Code :" + String.format("%d", bReasonCode);
            }
        }
    }

    public byte GetKmMessage()
    {
        return this.kmMessage;
    }

    public byte GetSubType()
    {
        return this.subType;
    }

    public void SetSubType(byte subType)
    {
        this.subType = subType;
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

    public byte[] GetEffDate()
    {
        return this.effDate;
    }

    public void SetEffDate(byte[] effDate)
    {
        this.effDate = super.SafeSetByteArray(this.effDate,effDate);
    }

    public byte GetTNum()
    {
        return this.tNum;
    }

    public void SetTNum(byte tNum)
    {
        this.tNum = tNum;
    }

    public byte[] GetsNum()
    {
        return this.sNum;
    }

    public void SetSNum(byte[] sNum)
    {
        this.sNum = super.SafeSetByteArray(this.sNum,sNum);
    }

    public byte GetReason()
    {
        return this.reason;
    }

    public void SetReason(byte reason)
    {
        try
        {
            switch (reason)
            {
                case KM_REASON.DELETION_KMAC_CORRUPTION,
                        KM_REASON.DELETION_TERMINATION_OF_SERVICE->
                {
                    /* 리즌코드 체크 */
                }
                default ->throw new IllegalArgumentException("reason value error. expected values (0000 0001 or 0000 0010)");
            }
        }
        catch (IllegalArgumentException e )
        {
            super.IsExceptionPrintingAndWriteLog(e);
        }
        finally
        {
            this.reason = reason;
        }
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