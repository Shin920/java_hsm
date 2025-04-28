package Message.offline.entity;

import Message.CodecUtil;
import Message.constant.Common.*;
import Message.constant.Offline.*;
import Message.offline.entity.sub.OfflineKeyStruct;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.LinkedList;
import java.util.Queue;

public class ReplaceAllKeys extends CodecUtil
{
    /**
     *  KEY_MESSAGE_AUTH_ALGO  : CRYPT_3DES_ECB(0x01), RESERVED(0x02), NDEFINED(0x03)
     *  {@link KEY_MESSAGE_AUTH_ALGO} -> Values from linked classes can be used
     * */
    private byte eAlgo;
    private byte[] kNum = new byte[OFFLINE_KEY_MESSAGE_SIZE.K_NUM_SIZE];
    private OfflineKeyStruct[] KeyStruct = null;
    private byte[] cbcMac = new byte[COMMON_SIZE.CBC_MAC_SIZE];

    /**
     * Structure of REPLACE_ALL_KEYS Request
     * @param eAlgo Algorithm used for KMAC encryption/decryption
     * @param kNum Number z of triple-keys contained in the structure
     * @param KeyStruct Key structure containing the triple-key itself and all additional properties/parameters (k=1 to z). K-STRUCT shall be greater or equal to ‘1’
     * @param cbcMac CBC-MAC
     */
    public ReplaceAllKeys(byte eAlgo, byte[] kNum, OfflineKeyStruct[] KeyStruct, byte[] cbcMac)
    {
        SetEAlgo(eAlgo);
        SetKNum(kNum);
        SetKeyStruct(KeyStruct);
        SetCbcMac(cbcMac);
    }

    public ReplaceAllKeys() {}

    /***
     * 직렬화된 바이트 배열을 통해 초기화 진행
     * @param bReplaceAllMessage 직렬화된 바이트 배열
     */
    public ReplaceAllKeys(byte[] bReplaceAllMessage) throws IllegalArgumentException
    {
        if(DecodeMessage(bReplaceAllMessage) != OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_SUCCESSFULLY_PROCESSED)
        {
            throw new IllegalArgumentException(EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
        }
    }

    /***
     * 직렬화된 바이트 배열을 통해 초기화 진행
     * @param bReplaceAllMessage 직렬화된 바이트 배열
     * @return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE [0,5,12,13]
     */
    public int DecodeMessage(byte[] bReplaceAllMessage)
    {
        try
        {
            return DeserializeFromBytes(bReplaceAllMessage);
        }
        catch (Exception e)
        {
            super.IsExceptionPrintingAndWriteLog(e);
            return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_ETC_ERROR;
        }
    }

    /***
     *
     * @return 구조체 필드 인스턴스들의 값을 바이트배열로 직렬화하여 반환
     */
    public byte[] EncodeObject(){
        try
        {
            if(this.KeyStruct == null)
            {
                throw new IOException("k_struct is Null");
            }
            byte[] bKStructPacket = new byte[COMMON_SIZE.EMPTY];
            for(OfflineKeyStruct ob : this.KeyStruct)
            {
                bKStructPacket = super.AddPacket(bKStructPacket,ob.EncodeObject());
            }
            return super.SerializeMultipleByteArrays(
                    new byte[]{this.eAlgo},
                    this.kNum,
                    bKStructPacket,
                    this.cbcMac
            );
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
    public int GetSize(){
        return OFFLINE_KEY_MESSAGE_SIZE.E_ALGO_SIZE + kNum.length + (KeyStruct != null ? KeyStruct.length * KeyStruct[0].GetSize() : 0) + cbcMac.length;
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
                this.eAlgo = dis.readByte();
                if(!CheckOfflineKeyMsgAuthAlgo(this.eAlgo)) /* 인증 알고리즘 확인*/
                {
                    IsExceptionPrintingAndWriteLog( new IllegalArgumentException("[ReplaceAllKeys] authAlgo value Error "));
                    return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_DECRYPTION_ALGORITHM_NOT_IMPLEMENTATION;
                }

                dis.readFully(this.kNum);
                Queue<byte[]> k_structPacket = new LinkedList<>();
                do {
                    byte bLength = dis.readByte();
                    byte[] bKmcId = new byte[COMMON_SIZE.ETCS_STRUCT_SIZE];
                    dis.readFully(bKmcId);
                    byte[] bSerialNumber = new byte[OFFLINE_KEY_MESSAGE_SIZE.SERIAL_SIZE];
                    dis.readFully(bSerialNumber);
                    byte[] bEnc = new byte[OFFLINE_KEY_MESSAGE_SIZE.KMAC_SIZE];
                    dis.readFully(bEnc);
                    byte[] bPeerNum = new byte[OFFLINE_KEY_MESSAGE_SIZE.PEER_NUM_SIZE];
                    dis.readFully(bPeerNum);
                    int nPeerIdLength = ConvertByteArrayToInt(bPeerNum) * COMMON_SIZE.ETCS_STRUCT_SIZE;

                    byte[] nPeerId = new byte[nPeerIdLength];
                    dis.readFully(nPeerId);  /* EOF 익셉션 자주 발생하는 부분 */

                    byte[] bValidPeriod = new byte[COMMON_SIZE.VALID_PERIOD_STRUCT_SIZE];
                    dis.readFully(bValidPeriod);
                    k_structPacket.add(
                            super.SerializeMultipleByteArrays(
                                    new byte[]{bLength},
                                    bKmcId,
                                    bSerialNumber,
                                    bEnc,
                                    bPeerNum,
                                    nPeerId,
                                    bValidPeriod
                            ));
                    /* CRC 사이즈 또는 그 이하로 남는다면 남은 K_STRUCT 가 없음  */
                    if (dis.available() <= COMMON_SIZE.CBC_MAC_SIZE)
                    {
                        break;
                    }
                } while (true);
                int nPacketSize = k_structPacket.size();
                this.KeyStruct = new OfflineKeyStruct[nPacketSize];
                for (int idx = 0; idx < nPacketSize; idx++)
                {
                    this.KeyStruct[idx] = new OfflineKeyStruct();
                    int nResult = this.KeyStruct[idx].DecodeMessage(k_structPacket.poll());
                    if(nResult != OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_SUCCESSFULLY_PROCESSED)
                    {
                        return nResult;
                    }
                }

                if( super.ConvertByteArrayToInt(this.kNum) != this.KeyStruct.length )
                {
                    IsExceptionPrintingAndWriteLog(new IllegalArgumentException("The number of k-num and keyStruct is not the same"));
                    return OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_INCONSISTENCY_DETECTED_IN_THE_RECEIVED_REQUEST;
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


    public byte GetEAlgo()
    {
        return eAlgo;
    }

    public void SetEAlgo(byte e_algo)
    {
        switch (e_algo)
        {
            case KEY_MESSAGE_AUTH_ALGO.CRYPT_3DES_ECB,
                    KEY_MESSAGE_AUTH_ALGO.RESERVED,
                    KEY_MESSAGE_AUTH_ALGO.NDEFINED ->
            {
                this.eAlgo = e_algo;
            }
            default -> throw new IllegalStateException("e_algo value not supported : " + (int)e_algo);
        }
    }

    public byte[] GetKNum()
    {
        return this.kNum;
    }

    public void SetKNum(byte[] k_num)
    {
        this.kNum = super.SafeSetByteArray(this.kNum,k_num);
    }

    public OfflineKeyStruct[] GetKeyStruct()
    {
        return this.KeyStruct;
    }

    public void SetKeyStruct(OfflineKeyStruct[] k_struct)
    {
        this.KeyStruct = k_struct;
    }

    public byte[] GetCbcMac()
    {
        return this.cbcMac;
    }

    public void SetCbcMac(byte[] cbc_mac)
    {
        this.cbcMac = super.SafeSetByteArray(this.cbcMac,cbc_mac);
    }

}
