package Message.offline.entity.sub;

import Message.CodecUtil;
import Message.constant.Common.*;
import Message.EtcsInfo;
import Message.ValidPeriod;
import Message.constant.Offline.*;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;

/**
 * Structure of K-STRUCT
 * @field length -> Key length in octets (24 for KMAC)
 * @field kmc_id -> Unique identification of the KMC that issued the authentication key
 * @field serial_number -> Unique serial number of the key
 * @field ENC(KMAC) -> Authentication key encrypted with transport key KTRANS-2
 * @field peer_num -> Number j of peer (on-board or trackside) ETCS entities stored in the structure. PEER-NUM shall be greater or equal to ‘1’
 * @field  peer_id -> ETCS ID Expanded of peer entity stored in the structure (i = 1 to j)
 * @field valid_period -> Validity period
 * */
public class OfflineKeyStruct extends CodecUtil
{
    private byte length;
    private EtcsInfo KmEtcsIdExp = new EtcsInfo();
    private byte[] sNum = new byte[OFFLINE_KEY_MESSAGE_SIZE.SERIAL_SIZE];
    private byte[] enc = new byte[OFFLINE_KEY_MESSAGE_SIZE.KMAC_SIZE];
    private byte[] peerNum = new byte[OFFLINE_KEY_MESSAGE_SIZE.PEER_NUM_SIZE];
    private EtcsInfo[] EtcsIdExpPeer = null;
    private ValidPeriod validPeriod = new ValidPeriod();

    public OfflineKeyStruct(){ }

    /**
     * k-struct 초기화
     * @param length Key length in octets (24 for KMAC)
     * @param kmEtcsIdExp Unique identification of the KMC that issued the authentication key
     * @param sNum Unique serial number of the key (together with the KM-ETCS-ID-EXP, this identifies the triple-key unambiguously)
     * @param enc Authentication key encrypted with transport key KTRANS-2
     * @param peerNum Number j of peer (on-board or trackside) ETCS entities stored in the structure. PEER-NUM shall be greater or equal to ‘1’
     * @param etcsIdExpPeer ETCS ID Expanded of peer entity stored in the structure
     * @param validPeriod Validity period
     */
    public OfflineKeyStruct(byte length, EtcsInfo kmEtcsIdExp, byte[] sNum, byte[] enc, byte[] peerNum, EtcsInfo[] etcsIdExpPeer, ValidPeriod validPeriod) {
        SetLength(length);
        SetKmEtcsIdExp(kmEtcsIdExp);
        SetSNum(sNum);
        SetEnc(enc);
        SetPeerNum(peerNum);
        SetEtcsIdExpPeer(etcsIdExpPeer);
        SetValidPeriod(validPeriod);
    }

    /***
     * 직렬화된 k-struct 바이트배열을 입력받아 클래스 초기화
     * @param bOfflineKeyMessage 직렬화된 k-struct 바이트배열
     */
    public OfflineKeyStruct(byte[] bOfflineKeyMessage) throws IllegalArgumentException
    {
        if(DecodeMessage(bOfflineKeyMessage) != OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_SUCCESSFULLY_PROCESSED)
        {
            throw new IllegalArgumentException(EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
        }
    }

    /***
     * 직렬화된 k-struct 바이트배열을 입력받아 클래스 초기화
     * @param bOfflineKeyMessage 직렬화된 k-struct 바이트배열
     */
    public int DecodeMessage(byte[] bOfflineKeyMessage)
    {
        try
        {
            return DeserializeFromBytes(bOfflineKeyMessage);
        }
        catch (Exception e)
        {
            super.IsExceptionPrintingAndWriteLog(e);
            return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_ETC_ERROR;
        }
    }

    public byte[] EncodeObject()
    {
        try
        {
            byte[] bPeerPacket = new byte[COMMON_SIZE.EMPTY];
            for(EtcsInfo EtcsObject : EtcsIdExpPeer)
            {
                bPeerPacket = super.AddPacket(bPeerPacket,EtcsObject.EncodeObject());
            }

            return super.SerializeMultipleByteArrays(
                    new byte[]{length},
                    this.KmEtcsIdExp.EncodeObject(),
                    this.sNum,
                    this.enc,
                    this.peerNum,
                    bPeerPacket,
                    this.validPeriod.EncodeObject()
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
            return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_MESSAGE_LENGTH_ERROR;
        }

        try (ByteArrayInputStream bais = new ByteArrayInputStream(byteArrayInputStream);
             DataInputStream dis = new DataInputStream(bais))
        {
            try { /* EOF check */
                this.length = dis.readByte();

                byte[] temp_kmcId = new byte[COMMON_SIZE.ETCS_STRUCT_SIZE];
                dis.readFully(temp_kmcId);
                this.KmEtcsIdExp.DecodeMessage(temp_kmcId);

                dis.readFully(this.sNum);
                dis.readFully(this.enc);
                dis.readFully(this.peerNum);

                int nPeerCnt = super.ConvertByteArrayToInt(this.peerNum);
                this.EtcsIdExpPeer = new EtcsInfo[nPeerCnt];
                for (int idx = 0; idx < nPeerCnt; idx++)
                {
                    byte[] bPeerEtcsId = new byte[COMMON_SIZE.ETCS_STRUCT_SIZE];
                    dis.readFully(bPeerEtcsId);
                    this.EtcsIdExpPeer[idx] = new EtcsInfo(bPeerEtcsId);
                }

                byte[] bValid = new byte[COMMON_SIZE.VALID_PERIOD_STRUCT_SIZE];
                dis.readFully(bValid);
                this.validPeriod.DecodeMessage(bValid);

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

    public int GetSize()
    {
        if(this.EtcsIdExpPeer == null)
        {
            return super.ERROR_CODE;
        }
        return OFFLINE_KEY_MESSAGE_SIZE.LENGTH_FILED_SIZE + this.KmEtcsIdExp.GetSize() + this.sNum.length + this.enc.length +
                this.peerNum.length + (this.EtcsIdExpPeer.length * this.EtcsIdExpPeer[0].GetSize()) + this.validPeriod.GetSize();
    }

    public byte GetLength()
    {
        return this.length;
    }

    public void SetLength(byte length)
    {
        this.length = length;
    }

    public EtcsInfo GetKmEtcsIdExp()
    {
        return this.KmEtcsIdExp;
    }

    public void SetKmEtcsIdExp(EtcsInfo kmEtcsIdExp)
    {
        this.KmEtcsIdExp = kmEtcsIdExp;
    }

    public byte[] GetSNum()
    {
        return this.sNum;
    }

    public void SetSNum(byte[] sNum)
    {
        this.sNum = super.SafeSetByteArray(this.sNum,sNum);
    }

    public byte[] GetEnc()
    {
        return this.enc;
    }

    public void SetEnc(byte[] enc)
    {
        this.enc = super.SafeSetByteArray(this.enc,enc);
    }

    public byte[] GetPeerNum()
    {
        return peerNum;
    }

    public void SetPeerNum(byte[] peerNum)
    {
        this.peerNum = super.SafeSetByteArray(this.peerNum,peerNum);
    }

    public EtcsInfo[] GetEtcsIdExpPeer()
    {
        return this.EtcsIdExpPeer;
    }

    public void SetEtcsIdExpPeer(EtcsInfo[] etcsIdExpPeer)
    {
        this.EtcsIdExpPeer = etcsIdExpPeer;
        this.peerNum = super.IntegerToByteArray(etcsIdExpPeer.length,this.peerNum.length);
    }

    public ValidPeriod GetValidPeriod()
    {
        return this.validPeriod;
    }

    public void SetValidPeriod(ValidPeriod validPeriod) {
        this.validPeriod = validPeriod;
    }
}
