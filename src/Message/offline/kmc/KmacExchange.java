package Message.offline.kmc;

import Message.CodecUtil;
import Message.EtcsInfo;
import Message.ValidPeriod;
import Message.constant.Common.*;
import Message.constant.Offline.*;
import java.io.*;

/**
 * KMAC Exchange request between off-line KM Domains.
 * @field km_msg -> KMAC exchange message.
 * @field ob_etcs_id -> The ETCS-ID expanded of the On-Board ERTMS Identity. It is unique per On-Board.
 * @field tr_struct -> The Trackside struct
 * @field KmEtcsIdIssuer -> Issuer KM ETCS ID
 * @field KmEtcsIdTarget -> Target KM ETCS ID
 * @field issue_date -> The issue date of the key management message.
 * @field valid_period -> The valid period for the key management message.
 * @field tnum -> This Transaction Number identifies unambiguously the negative acknowledgment and is equal to the TNUM received in the aborted KMAC message
 * @field enc -> Encrypted data for key management.
 * @field snum -> Serial number of the message.
 * @field cbc_mac -> Message authentication code for the message.
 */
public class KmacExchange extends CodecUtil {

    private final byte kmMessage = OFFLINE_KM_MESSAGE.KMAC_EXCHANGE;
    private byte[] obEtcsId = new byte[KM_MESSAGE_SIZE.ID_SIZE];
    private TracksidePeer TracksidePeer = new TracksidePeer();
    private EtcsInfo KmEtcsIdIssuer = new EtcsInfo();
    private EtcsInfo KmEtcsIdTarget = new EtcsInfo();
    private byte[] issueDate = new byte[KM_MESSAGE_SIZE.ISSUE_DATA_SIZE];
    //public byte[] valid_period = new byte[8];
    private ValidPeriod validPeriod = new ValidPeriod();
    private byte tNum;
    private byte[] enc = new byte[KM_MESSAGE_SIZE.KMAC_SIZE];
    private byte[] sNum = new byte[KM_MESSAGE_SIZE.SNUM_SIZE];
    private byte[] cbcMac = new byte[COMMON_SIZE.CBC_MAC_SIZE];

    public KmacExchange(){ }

    /**
     * 기본 생성자
     * @param obEtcsId The ETCS-ID expanded of the On-Board ERTMS Identity. It is unique per On-Board.
     * @param tracksidePeer  The Trackside struct
     * @param kmEtcsIdIssuer Issuer KM ETCS ID
     * @param kmEtcsIdTarget Target KM ETCS ID
     * @param issueDate The issue date of the key management message.
     * @param validPeriod The valid period for the key management message.
     * @param tNum This Transaction Number identifies unambiguously the negative acknowledgment and is equal to the TNUM received in the aborted KMAC message
     * @param enc (KMAC)Encrypted data for key management.
     * @param sNum Serial number of the message.
     * @param cbcMac Message authentication code for the message.
     */
    public KmacExchange(byte[] obEtcsId, TracksidePeer tracksidePeer, EtcsInfo kmEtcsIdIssuer, EtcsInfo kmEtcsIdTarget, byte[] issueDate, ValidPeriod validPeriod, byte tNum, byte[] enc, byte[] sNum, byte[] cbcMac)
    {
        SetObEtcsId(obEtcsId);
        SetTracksidePeer(tracksidePeer);
        SetKmEtcsIdIssuer(kmEtcsIdIssuer);
        SetKmEtcsIdTarget(kmEtcsIdTarget);
        SetIssueDate(issueDate);
        SetValidPeriod(validPeriod);
        SetTNum(tNum);
        SetEnc(enc);
        SetSNum(sNum);
        SetCbcMac(cbcMac);
    }

    /**
     * Constructs a KMAC_EXCHANGE instance from the given byte array buffer.
     * This constructor initializes the fields of the class based on the buffer contents.
     *
     * @param byteArrayInputStream the byte array containing the data to initialize the fields
     */
    public KmacExchange(byte[] byteArrayInputStream) throws IllegalArgumentException
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

    private void DeserializeFromBytes(byte[] byteArrayInputStream) throws Exception
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

                dis.readFully(this.obEtcsId);

                byte bTrQuant = dis.readByte();
                byte[] bTrEtcsId = new byte[bTrQuant * KM_MESSAGE_SIZE.ETCS_STRUCT_SIZE];
                dis.readFully(bTrEtcsId);

                /* Combine tr_quant and tr_etcs_id into one array */
                byte[] bCombinedArray = new byte[KM_MESSAGE_SIZE.TR_QUANT_SIZE + bTrEtcsId.length];
                bCombinedArray[KM_MESSAGE_IDX.TR_QUANT_IDX] = bTrQuant;
                System.arraycopy(bTrEtcsId, 0, bCombinedArray, 1, bTrEtcsId.length);
                this.TracksidePeer = new TracksidePeer(bCombinedArray);

                byte[] bTempEtcsId = new byte[KM_MESSAGE_SIZE.ETCS_STRUCT_SIZE];
                dis.readFully(bTempEtcsId);
                this.KmEtcsIdIssuer.DecodeMessage(bTempEtcsId);
                dis.readFully(bTempEtcsId);
                this.KmEtcsIdTarget.DecodeMessage(bTempEtcsId);

                dis.readFully(this.issueDate);
                byte[] bValidPeriod = new byte[KM_MESSAGE_SIZE.VALID_PERIOD_STRUCT_SIZE];
                dis.readFully(bValidPeriod);
                this.validPeriod.DecodeMessage(bValidPeriod);
                this.tNum = dis.readByte();
                dis.readFully(this.enc);
                dis.readFully(this.sNum);
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

    private byte[] SerializeToBytes() throws IOException
    {
        return super.SerializeMultipleByteArrays(
                new byte[]{this.kmMessage},
                this.obEtcsId,
                this.TracksidePeer.EncodeObject(),
                this.KmEtcsIdIssuer.EncodeObject(),
                this.KmEtcsIdTarget.EncodeObject(),
                this.issueDate,
                this.validPeriod.EncodeObject(),
                new byte[]{this.tNum},
                this.enc,
                this.sNum,
                this.cbcMac
        );
    }

    /***
     *
     * @return 구조체 크기 반환
     */
    public int GetSize()
    {
        return COMMON_SIZE.EMPTY + this.obEtcsId.length + this.TracksidePeer.GetSize() + this.KmEtcsIdIssuer.GetSize() + this.KmEtcsIdTarget.GetSize() +
                this.issueDate.length + this.validPeriod.GetSize() + KM_MESSAGE_SIZE.TNUM_SIZE + this.enc.length + this.sNum.length + this.cbcMac.length;
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
        this.obEtcsId = obEtcsId;
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
        this.issueDate = super.SafeSetByteArray(this.issueDate, issueDate);
    }

    public ValidPeriod GetValidPeriod()
    {
        return this.validPeriod;
    }

    public void SetValidPeriod(ValidPeriod validPeriod)
    {
        this.validPeriod = validPeriod;
    }

    public byte GetTNum()
    {
        return this.tNum;
    }

    public void SetTNum(byte tNum)
    {
        this.tNum = tNum;
    }

    public byte[] GetEnc()
    {
        return this.enc;
    }

    public void SetEnc(byte[] enc)
    {
        this.enc = enc;
    }

    public byte[] GetSNum()
    {
        return this.sNum;
    }

    public void SetSNum(byte[] sNum)
    {
        this.sNum = sNum;
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
