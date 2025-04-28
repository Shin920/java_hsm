package Message.offline.kmc;

import Message.CodecUtil;
import Message.EtcsInfo;
import Message.constant.Common.*;
import Message.constant.Offline.*;
import java.io.*;


/**
 *  038 key_offline[kmc<->kmc] KM_MESSAGE  : KMAC_NEGACK(0b00000000)
 * @field km_msg -> KMAC negative acknowledgment message.
 * @field ab_message -> Codification of the aborted KM message. Authorized values are KMAC-EXCHANGE, KMAC-DELETION or KMAC-UPDATE
 * @field ob_etcs_id -> The ETCS-ID expanded of the On-Board ERTMS Identity. It is unique per On-Board.
 * @field km_etcs_id1 -> Issuer KM ETCS ID
 * @field km_etcs_id2 -> Target KM ETCS ID
 * @field issue_date -> The issue date of the key management message.
 * @field tnum -> This Transaction Number identifies unambiguously the negative acknowledgment and is equal to the TNUM received in the aborted KMAC message
 * @field reason -> The reason for the negative acknowledgment.
 * @field cbc_mac -> Message authentication code for the message.
 */
public class KmacNegack extends CodecUtil {
    private final byte kmMessage = OFFLINE_KM_MESSAGE.KMAC_NEGACK;
    private byte AbMessage; /* 중단된 KM 메시지 (교환,삭제,업데이트 요청 메시지 중) */
    private byte[] obEtcsId = new byte[KM_MESSAGE_SIZE.ID_SIZE];
    private EtcsInfo KmEtcsIdIssuer = new EtcsInfo();
    private EtcsInfo KmEtcsIdTarget = new EtcsInfo();
    private byte[] issueDate = new byte[KM_MESSAGE_SIZE.ISSUE_DATA_SIZE];
    private byte tNum;
    private byte reason;
    private byte[] cbcMac = new byte[COMMON_SIZE.CBC_MAC_SIZE];

    /**
     * 기본 생성자
     * @param AbMessage Codification of the aborted KM message. Authorized values are KMAC-EXCHANGE, KMAC-DELETION or KMAC-UPDATE
     * @param obEtcsId The ETCS-ID expanded of the On-Board ERTMS Identity. It is unique per On-Board.
     * @param KmEtcsIdIssuer Issuer KM ETCS ID
     * @param KmEtcsIdTarget Target KM ETCS ID
     * @param issueDate The issue date of the key management message.
     * @param tNum This Transaction Number identifies unambiguously the negative acknowledgment and is equal to the TNUM received in the aborted KMAC message
     * @param reason The reason for the negative acknowledgment.
     * @param cbcMac Message authentication code for the message.
     */
    public KmacNegack(byte AbMessage, byte[] obEtcsId, EtcsInfo KmEtcsIdIssuer, EtcsInfo KmEtcsIdTarget, byte[] issueDate, byte tNum, byte reason, byte[] cbcMac)
    {
        SetAbMessage(AbMessage);
        SetObEtcsId(obEtcsId);
        SetKmEtcsIdIssuer(KmEtcsIdIssuer);
        SetKmEtcsIdTarget(KmEtcsIdTarget);
        SetIssueDate(issueDate);
        SetTNum(tNum);
        SetReason(reason);
        SetCbcMac(cbcMac);
    }

    public KmacNegack(){}

    /**
     * Constructs a KMAC_NEGACK instance from the given byte array buffer.
     * This constructor initializes the fields of the class based on the buffer contents.
     *
     * @param byteArrayInputStream the byte array containing the data to initialize the fields
     */
    public KmacNegack(byte[] byteArrayInputStream) throws IllegalArgumentException
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
     * @param byteArrayInputStream the byte array containing the data to initialize the fields
     */
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


    /**
     * Data to msg
     * @return Byte-serialize field instance values
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

    /**
     * Constructs a KMAC_NEGACK instance from the given byte array buffer.
     * This constructor initializes the fields of the class based on the buffer contents.
     *
     * @param KmacDeletionObject Object for initializing default values in fields
     */
    public KmacNegack(KmacDeletion KmacDeletionObject)
    {
        SetIncorporateObject(KmacDeletionObject);
    }

    /**
     * Constructs a KMAC_NEGACK instance from the given byte array buffer.
     * This constructor initializes the fields of the class based on the buffer contents.
     *
     * @param KmacUpdateObject Object for initializing default values in fields
     */
    public KmacNegack(KmacUpdate KmacUpdateObject)
    {
        SetIncorporateObject(KmacUpdateObject);
    }

    /**
     * Constructs a KMAC_NEGACK instance from the given byte array buffer.
     * This constructor initializes the fields of the class based on the buffer contents.
     *
     * @param KmacExchangeObject Object for initializing default values in fields
     */
    public KmacNegack(KmacExchange KmacExchangeObject)
    {
        SetIncorporateObject(KmacExchangeObject);
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
            try {
                /* Read and ignore km_msg, because it's a constant */
                byte bReadKmMsg = dis.readByte();
                if (bReadKmMsg != this.kmMessage) {
                    throw new IOException("Invalid km_msg value.");
                }

                /* Read the rest of the fields */
                this.AbMessage = dis.readByte();
                dis.readFully(this.obEtcsId);
                dis.readFully(this.KmEtcsIdIssuer.EncodeObject());
                dis.readFully(this.KmEtcsIdTarget.EncodeObject());
                dis.readFully(this.issueDate);
                this.tNum = dis.readByte();
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
    private byte[] SerializeToBytes() throws IOException {
        return super.SerializeMultipleByteArrays(
                new byte[]{this.kmMessage,this.AbMessage},
                this.obEtcsId,
                this.KmEtcsIdIssuer.EncodeObject(),
                this.KmEtcsIdTarget.EncodeObject(),
                this.issueDate,
                new byte[]{this.tNum,reason},
                this.cbcMac
        );
    }

    /***
     *
     * @return 구조체의 크기 반환
     */
    public int GetSize()
    {
        return KM_MESSAGE_SIZE.KM_MESSAGE_SIZE + KM_MESSAGE_SIZE.KM_MESSAGE_SIZE + this.obEtcsId.length + this.KmEtcsIdIssuer.GetSize() + this.KmEtcsIdTarget.GetSize()
                + this.issueDate.length + KM_MESSAGE_SIZE.TNUM_SIZE + KM_MESSAGE_SIZE.REASON_SIZE + this.cbcMac.length;
    }

    /**
     * set field instance Reason and cbc_mac
     * @param bReasonCode Expected Reason Code [ 0b00000001,0b00000010,0b00000011 ]
     * @param bCbcMac cbc_mac value
     * @return Whether the setting was successful or not
     * */
    public boolean SetReasonAndCbcMac(byte bReasonCode, byte[] bCbcMac)
    {
        switch(bReasonCode)
        {
            case KM_REASON.NEGACK_REASON_CBC_ERROR,
                    KM_REASON.NEGACK_REASON_UNKNOWN_ETCS_ID,
                    KM_REASON.NEGACK_REASON_KMAC_PARITY_ERROR ->
            {
                this.reason = bReasonCode;
                this.cbcMac = bCbcMac;
                return true;
            }
            default ->
            {
                return false;
            }
        }
    }

    public String GetReasonCodeToString()
    {
        return GetReasonCodeToString(this.reason);
    }

    public String GetReasonCodeToString(byte bReasonCode)
    {
        switch(bReasonCode)
        {
            case KM_REASON.NEGACK_REASON_CBC_ERROR ->
            {
                return "Incorrect CBC_MAC calculation of received KMAC message";
            }
            case KM_REASON.NEGACK_REASON_UNKNOWN_ETCS_ID ->
            {
                return "Unknown OBU ETCS-ID";
            }
            case KM_REASON.NEGACK_REASON_KMAC_PARITY_ERROR ->
            {
                return "Invalid KMAC parity";
            }
            default ->
            {
                return "Unknown reason Code :" + String.format("%d",bReasonCode);
            }
        }
    }

    /**
     * 바이트 배열 타입이 KMAC_NEGACK 이 아니라면 타입에 해당하는 객체를 생성한 후 오버로딩된 SetIncorporateMsg 메서드를 통해 NEGACK 객체 구성
     * @param bKmacNegackMessage instance to incorporate
     * @return Incorporate success or not
     */
    private boolean IncorporateMsgFromBuffer(byte[] bKmacNegackMessage)
    {
        try
        {
            /* 바이트 배열 타입이 KMAC_NEGACK 이 아니라면 타입에 해당하는 객체를 생성한 후
             * 오버로딩된 SetIncorporateMsg 메서드를 통해 NEGACK 객체 구성 */
            switch ((int) bKmacNegackMessage[COMMON_SIZE.ETCS_MESSAGE_TYPE_IDX])
            {
                case OFFLINE_KM_MESSAGE.KMAC_NEGACK ->
                {
                    DeserializeFromBytes(bKmacNegackMessage);
                }
                case OFFLINE_KM_MESSAGE.KMAC_EXCHANGE ->
                {
                    SetIncorporateObject(new KmacExchange(bKmacNegackMessage));
                }
                case OFFLINE_KM_MESSAGE.KMAC_DELETION ->
                {
                    SetIncorporateObject(new KmacDeletion(bKmacNegackMessage));
                }
                case OFFLINE_KM_MESSAGE.KMAC_UPDATE ->
                {
                    SetIncorporateObject(new KmacUpdate(bKmacNegackMessage));
                }
                default -> throw new IllegalArgumentException("Illegal Argument Exception");
            }
            return true;
        }catch (Exception e){
            super.IsExceptionPrintingAndWriteLog(e);
        }
        return false;
    }

    public void SetIncorporateObject(KmacExchange kmacExchange)
    {
        this.AbMessage = kmacExchange.GetKmMessage();
        this.obEtcsId = kmacExchange.GetObEtcsId();
        this.KmEtcsIdIssuer = kmacExchange.GetKmEtcsIdIssuer();
        this.KmEtcsIdTarget = kmacExchange.GetKmEtcsIdTarget();
        this.issueDate = kmacExchange.GetIssueDate();
        this.tNum = kmacExchange.GetTNum();

    }

    public void SetIncorporateObject(KmacDeletion kmacDeletion)
    {
        this.AbMessage = kmacDeletion.GetKmMessage();
        this.obEtcsId = kmacDeletion.GetObEtcsId();
        this.KmEtcsIdIssuer = kmacDeletion.GetKmEtcsIdIssuer();
        this.KmEtcsIdTarget = kmacDeletion.GetKmEtcsIdTarget();
        this.issueDate = kmacDeletion.GetIssueDate();
        this.tNum = kmacDeletion.GetTNum();

    }

    public void SetIncorporateObject(KmacUpdate kmacUpdate)
    {
        this.AbMessage = kmacUpdate.GetKmMessage();
        this.obEtcsId = kmacUpdate.GetObEtcsId();
        this.KmEtcsIdIssuer = kmacUpdate.GetKmEtcsIdIssuer();
        this.KmEtcsIdTarget = kmacUpdate.GetKmEtcsIdTarget();
        this.issueDate = kmacUpdate.GetIssueDate();
        this.tNum = kmacUpdate.GetTNum();

    }

    public byte GetKmMessage()
    {
        return this.kmMessage;
    }

    public byte GetAbMessage()
    {
        return this.AbMessage;
    }

    public void SetAbMessage(byte abMessage)
    {
        this.AbMessage = abMessage;
    }

    public byte[] GetObEtcsId()
    {
        return this.obEtcsId;
    }

    public void SetObEtcsId(byte[] obEtcsId)
    {
        this.obEtcsId = obEtcsId;
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
        this.issueDate = issueDate;
    }

    public byte GetTNum()
    {
        return this.tNum;
    }

    public void SetTNum(byte tNum)
    {
        this.tNum = tNum;
    }

    public byte GetReason()
    {
        return this.reason;
    }

    public void SetReason(byte reason)
    {
        try
        {
            switch(reason) /* Reason code value check*/
            {
                case KM_REASON.NEGACK_REASON_UNKNOWN_ETCS_ID/*0000 0010*/,
                        KM_REASON.NEGACK_REASON_KMAC_PARITY_ERROR/*0000 0011*/,
                        KM_REASON.NEGACK_REASON_CBC_ERROR/*0000 0001*/->{
                }
                default ->
                {
                    throw  new IOException("Reason code value Error expected value : (0000 0001 or 0000 0010 or 0000 0011)");
                }
            }
        }
        catch(IOException e)
        {
            super.IsExceptionPrintingAndWriteLog(e);
        }
        finally
        {
            /* 예외 발생 여부와 상관없이 reason 값을 설정 */
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