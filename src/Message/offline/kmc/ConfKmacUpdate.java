package Message.offline.kmc;

import Message.CodecUtil;
import Message.EtcsInfo;
import Message.constant.Common.*;
import Message.constant.Offline.*;
import java.io.*;

/**
 *  038 key_offline[kmc<->kmc] KM_MESSAGE : CONF_KMAC_UPDATE(0b00010001)
 * @field km_msg -> Confirmation of KMAC update message.
 * @field ob_etcs_id -> The ETCS-ID expanded of the On-Board ERTMS Identity. It is unique per On-Board.
 * @field tr_struct -> The Trackside struct
 * @field km_etcs_id1 -> Issuer KM ETCS ID
 * @field km_etcs_id2 -> Target KM ETCS ID
 * @field issue_date -> The issue date of the key management message.
 * @field tnum -> This Transaction Number identifies unambiguously the negative acknowledgment and is equal to the TNUM received in the aborted KMAC message
 * @field cbc_mac -> Message authentication code for the message.
 */
public class ConfKmacUpdate extends CodecUtil
{
    private final byte kmMessage = OFFLINE_KM_MESSAGE.CONF_KMAC_UPDATE;
    private byte[] obEtcsId = new byte[KM_MESSAGE_SIZE.ID_SIZE];
    private TracksidePeer TracksidePeer = new TracksidePeer();
    private EtcsInfo KmEtcsIdIssuer = new EtcsInfo();
    private EtcsInfo KmEtcsIdTarget = new EtcsInfo();
    private byte[] issueDate = new byte[KM_MESSAGE_SIZE.ID_SIZE];
    private byte tNum;
    private byte[] cbcMac = new byte[COMMON_SIZE.CBC_MAC_SIZE];

    public ConfKmacUpdate(){}

    /**
     * 기본 생성자
     * @param obEtcsId The ETCS-ID expanded of the On-Board ERTMS Identity. It is unique per On-Board.
     * @param tracksidePeer The Trackside struct
     * @param KmEtcsIdIssuer Issuer KM ETCS ID
     * @param KmEtcsIdTarget Target KM ETCS ID
     * @param issueDate The issue date of the key management message.
     * @param tNum This Transaction Number identifies unambiguously the negative acknowledgment and is equal to the TNUM received in the aborted KMAC message
     * @param cbcMac Message authentication code for the message.
     */
    public ConfKmacUpdate(byte[] obEtcsId, TracksidePeer tracksidePeer, EtcsInfo KmEtcsIdIssuer, EtcsInfo KmEtcsIdTarget, byte[] issueDate, byte tNum, byte[] cbcMac)
    {
        SetObEtcsId(obEtcsId);
        SetTracksidePeer(tracksidePeer);
        SetKmEtcsIdIssuer(KmEtcsIdIssuer);
        SetKmEtcsIdTarget(KmEtcsIdTarget);
        SetIssueDate(issueDate);
        SetTNum(tNum);
        SetCbcMac(cbcMac);
    }

    /**
     * Constructs a KMAC_NEGACK instance from the given byte array buffer.
     * This constructor initializes the fields of the class based on the buffer contents.
     *
     * @param kmacUpdate Object for initializing default values in fields
     */
    public ConfKmacUpdate(KmacUpdate kmacUpdate)
    {
        IncorporateKmacUpdate(kmacUpdate);
    }

    /**
     * Constructs a CONF_KMAC_UPDATE instance from the given byte array buffer.
     * This constructor initializes the fields of the class based on the buffer contents.
     *
     * @param byteArrayInputStream the byte array containing the data to initialize the fields
     * @throws ArrayIndexOutOfBoundsException if the buffer is too small to fill the fields
     */
    public ConfKmacUpdate(byte[] byteArrayInputStream) throws IllegalArgumentException
    {
        if(!DecodeMessage(byteArrayInputStream))
        {
            throw new IllegalArgumentException(EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
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

    private void DeserializeFromBytes(byte[] byteArrayInputStream) throws IOException
    {
        if (byteArrayInputStream == null || byteArrayInputStream.length == COMMON_SIZE.EMPTY)
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
                if (bReadKmMsg != this.kmMessage)
                {
                    throw new IOException("Invalid km_msg value.");
                }

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

                dis.readFully(this.issueDate);
                this.tNum = dis.readByte();
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

    /***
     *
     * @return 구조체의 크기 반환
     */
    public int GetSize()
    {
        return KM_MESSAGE_SIZE.KM_MESSAGE_SIZE + this.obEtcsId.length + this.TracksidePeer.GetSize() +
                this.KmEtcsIdIssuer.GetSize() + this.KmEtcsIdTarget.GetSize() + this.issueDate.length + KM_MESSAGE_SIZE.TNUM_SIZE + this.cbcMac.length;
    }

    /* Byte-serialize field instance values */
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

    private boolean IncorporateMsgFromBuffer(byte[] bConfKmacUpdateMessage)
    {
        try
        {
            switch (bConfKmacUpdateMessage[COMMON_SIZE.ETCS_MESSAGE_TYPE_IDX])
            {
                case OFFLINE_KM_MESSAGE.CONF_KMAC_UPDATE ->
                {
                    DeserializeFromBytes(bConfKmacUpdateMessage);
                }
                case OFFLINE_KM_MESSAGE.KMAC_UPDATE ->
                {
                    KmacUpdate msg = new KmacUpdate(bConfKmacUpdateMessage);
                    IncorporateKmacUpdate(msg);
                }
                default -> throw new IllegalStateException("Unexpected value: " + bConfKmacUpdateMessage[0]);
            }
            return true;
        } catch (IOException e)
        {
            /* type 을 제외한 value Error */
            super.IsExceptionPrintingAndWriteLog(e);
        }
        catch (IllegalStateException e)
        {
            // type Error
            super.IsExceptionPrintingAndWriteLog(e);
        }
        return false;

    }

    /**
     * Incorporates KMAC_UPDATE fields and methods into CONF_KMAC_UPDATE.
     * Ensure no essential inheritance and fields are missing.
     *
     * @param kmacUpdate KMAC_UPDATE instance to incorporate
     */
    private void IncorporateKmacUpdate(KmacUpdate kmacUpdate)
    {
        this.obEtcsId = kmacUpdate.GetObEtcsId();
        this.TracksidePeer = kmacUpdate.GetTracksidePeer();
        this.KmEtcsIdIssuer = kmacUpdate.GetKmEtcsIdIssuer();
        this.KmEtcsIdTarget = kmacUpdate.GetKmEtcsIdTarget();
        this.issueDate = kmacUpdate.GetIssueDate();
        this.tNum = kmacUpdate.GetTNum();
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
        KmEtcsIdTarget = kmEtcsIdTarget;
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
