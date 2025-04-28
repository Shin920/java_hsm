package codec.offlineEntity;

import Message.CodecUtil;
import Message.constant.Offline.*;
import Message.constant.Common;
import Message.EtcsInfo;
import Message.ValidPeriod;
import Message.offline.entity.*;
import Message.offline.entity.sub.OfflineHeader;
import Message.offline.entity.sub.OfflineKeyStruct;
import java.io.IOException;

/**
 *      오프라인 메시지 인코딩 클래스<p>
 *          헤더, 바디 필드 객체를 설정하고 설정된 클래스의 객체 인스턴스를 바이트 배열로 직렬화하여 반환시켜 주는 목적을 가짐<p>
 *      <객체 인스턴스 설정 방법><p>
 *      1. 생성자를 통한 필드 구성 -> 생성자에 Header 와 Body 오브젝트를 자유롭게 할당하여 필드 초기화<p>
 *      2. 객체를 통한 필드 구성 -> SetHeader , SetBody 메서드를 통해 필드 구성 <p>
 *      3. 객체별 생성 메서드를 통해 필드 구성 가능 <p>
 * */
public class OfflineKeyMsgEncoder extends CodecUtil
{
    private OfflineHeader Header;

    private ReplaceAllKeys ReplaceAllKeys;
    private DeleteAllKeys DeleteAllKeys;
    private AddAuthenticationKey AddAuthenticationKey;
    private DeleteKey DeleteKey;
    private ReplaceEtcsEntities ReplaceEtcsEntities;
    private UpdateKeyValidityPeriod UpdateKeyValidityPeriod;
    private InstallTransportKey InstallTransportKey;
    private ResponseNotify ResponseNotify;


    /* 생성자 ******************************************************************************************/
    public OfflineKeyMsgEncoder()
    {
        InitInstanceFiledValues(true);
    }

    /**
     * Header 설정
     */
    public OfflineKeyMsgEncoder(OfflineHeader header)
    {
        this();
        this.Header = header;
    }

    /**
     *  Body 설정
     */
    public <T> OfflineKeyMsgEncoder(T bodyObject) throws IllegalArgumentException
    {
        this();
        if(!SetBody(bodyObject))
        {
            throw new IllegalArgumentException(Common.EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
        }
    }

    /**
     * 클래스 초기화
     */
    public <T> OfflineKeyMsgEncoder(OfflineHeader header, T bodyObject) throws IllegalArgumentException
    {
        this(header);
        if(!SetBody(bodyObject))
        {
            throw new IllegalArgumentException(Common.EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
        }
    }

    /* 클래스 메서드 **************************************************************************************************************/

    public <T> byte[] EncodeObject(OfflineHeader header, T bodyObject)
    {
        SetHeader(header);
        return SetBody(bodyObject) ? EncodeObject() : super.MakeErrorPacket(1);
    }

    /**
     * 설정된 타입에 맞춰 헤더, 바디 클래스를 바이트 직렬화하여 합쳐서 반환
     */
    public byte[] EncodeObject()
    {
        boolean bResult = false;
        byte[] bResultBuffer = new byte[Common.COMMON_SIZE.EMPTY];
        try
        {
            if(!SettingHeaderLength()) /* 헤더 패킷 길이 설정 */
            {
                throw new IOException("Data size check fail");
            }

            byte[] bHeaderArray = Header.EncodeObject();
            byte[] bBodyArray = EncodeBodyObject(); /* 실패 시 throw 던져짐 */

            bResultBuffer = super.AddPacket(bHeaderArray,bBodyArray);

            WriteEncodeLog();
            bResult = true; /* 예외 적중이 없다면 정상 진행 완료 */
        }
        catch (NullPointerException | IOException | IllegalArgumentException e)
        {
            WriteErrorLog("[OfflineKeyMsgEncoder] Packet create fail for this Class.");
            super.IsExceptionPrintingAndWriteLog(e);
        }
        catch (Exception e) /* 처리되지 않은 예외 발생 */
        {
            WriteErrorLog("[OfflineKeyMsgEncoder] Unhandled exception occurred");
            super.IsExceptionPrintingAndWriteLog(e);
        }
        finally
        {
            return bResult ? bResultBuffer : new byte[]{ERROR_BYTE};
        }
    }

    /**
     * 헤더 타입에 맞춰 생성된 객체를 추적하여 사이즈 추출
     * @return Header Size + Body Size
     */
    public int GetSize()
    {
        try
        {
            int nBufferSize = Header.GetSize();
            switch (Header.GetMsgType()) /* 헤더의 타입 체크 */
            {
                case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_REPLACE_ALL_KEYS ->
                {
                    nBufferSize += ReplaceAllKeys.GetSize();
                }
                case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_DELETE_ALL_KEYS ->
                {
                    nBufferSize += DeleteAllKeys.GetSize();
                }
                case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_ADD_AUTHENTICATION_KEY ->
                {
                    nBufferSize += AddAuthenticationKey.GetSize();
                }
                case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_DELETE_KEY ->
                {
                    nBufferSize += DeleteKey.GetSize();
                }
                case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_REPLACE_ETCS_ENTITIES ->
                {
                    nBufferSize += ReplaceEtcsEntities.GetSize();
                }
                case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_UPDATE_KEY_VALIDITY_PERIOD ->
                {
                    nBufferSize += UpdateKeyValidityPeriod.GetSize();
                }
                case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_INSTALL_TRANSPORT_KEY ->
                {
                    nBufferSize += InstallTransportKey.GetSize();
                }
                case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_RESPONSE_NOTIFY ->
                {
                    nBufferSize += ResponseNotify.GetSize();
                }
                default ->
                {
                    return ERROR_CODE; /* Header type value Error */
                }
            }
            return nBufferSize;
        }
        catch (NullPointerException e)
        {
            String strError = String.format("The object is null. Msg type [%02X] ", Header.GetMsgType());
            NullPointerException exception = new NullPointerException(strError); /* 예외 재정의 */
            exception.setStackTrace(e.getStackTrace()); /* 스택 트레이스 복사 */
            super.IsExceptionPrintingAndWriteLog(exception);

            return ERROR_CODE; /* 예외처리 발생 시 에러버퍼 반환 */
        }
    }

    /**
     * 현재 설정된 헤더와 바디 구성에 맞춰 헤더의 길이 필드 설정
     * */
    public boolean SettingHeaderLength()
    {
        boolean bResult = true;
        int nStructSize = GetSize();
        if(Header != null)
        {
            byte[] bLengthBuffer;
            if(nStructSize != ERROR_CODE)
            {
                bLengthBuffer = super.IntegerToByteArray(nStructSize, Header.GetLength().length);
                Header.SetLength(bLengthBuffer);
            }
            else
            {
                bResult = false;
            }
        }
        else
        {
            WriteErrorLog("[OfflineKeyMsgEncoder] The length cannot be set because the header is a null value");
            bResult = false;
        }

        return bResult;
    }


    /**
     * 헤더에 설정되어있는 바디 객체에서 패킷 추출
     * @return BodyPacket
     * @throws Exception
     *                   <p>NullPointerException -> Header, Body filed reference error
     *                   <p>IllegalArgumentException Header Message Type value error
     */
    public byte[] EncodeBodyObject() throws Exception
    {
        byte[] bReturnErrorBuffer = super.MakeErrorPacket(4);
        try
        {
            switch (Header.GetMsgType()) /* 헤더의 타입 체크 */
            {
                case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_REPLACE_ALL_KEYS ->
                {
                    return ReplaceAllKeys.EncodeObject();
                }
                case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_DELETE_ALL_KEYS ->
                {
                    return DeleteAllKeys.EncodeObject();
                }
                case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_ADD_AUTHENTICATION_KEY ->
                {
                    return AddAuthenticationKey.EncodeObject();
                }
                case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_DELETE_KEY ->
                {
                    return DeleteKey.EncodeObject();
                }
                case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_REPLACE_ETCS_ENTITIES ->
                {
                    return ReplaceEtcsEntities.EncodeObject();
                }
                case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_UPDATE_KEY_VALIDITY_PERIOD ->
                {
                    return UpdateKeyValidityPeriod.EncodeObject();
                }
                case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_INSTALL_TRANSPORT_KEY ->
                {
                    return InstallTransportKey.EncodeObject();
                }
                case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_RESPONSE_NOTIFY ->
                {
                    return ResponseNotify.EncodeObject();
                }
                default ->
                {
                    throw new IllegalArgumentException("[OfflineKeyMsgEncoder] Header type value is not Defined OFFLINE_KEY_MESSAGE_TYPE");
                }
            }
        }
        catch (NullPointerException e)
        {
            /* 예외 메시지 형식 지정 */
            String strError = String.format("[OfflineKeyMsgEncoder] The object you are trying to extract packets from has not been initialized [Type value : %02x]", Header.GetMsgType());

            /* 새로운 NullPointerException 을 생성하고, 스택 트레이스를 설정 */
            NullPointerException newException = new NullPointerException(strError);
            newException.setStackTrace(e.getStackTrace());

            throw newException;
        }
    }

    private void WriteEncodeLog()
    {
        String strSuccessMsg = String.format("[OfflineKeyMsgEncoder] [Encode OK] %s message", CheckOfflineKeyMsgType(Header.GetMsgType()));
        WriteErrorLog(strSuccessMsg);
    }

    private void WriteFiledSetLog()
    {
        String strMsg = String.format("[OfflineKeyMsgEncoder] set Body(%s)", CheckOfflineKeyMsgType(Header.GetMsgType()));
        WriteErrorLog(strMsg);
    }

    /***
     * Initialize Filed instance values
     */
    private void InitInstanceFiledValues(boolean bHeaderInit)
    {
        if(bHeaderInit)
        {
            this.Header = new OfflineHeader();
        }

        ReplaceAllKeys = null;
        DeleteAllKeys = null;
        AddAuthenticationKey = null;
        DeleteKey = null;
        ReplaceEtcsEntities = null;
        UpdateKeyValidityPeriod = null;
        InstallTransportKey = null;
        ResponseNotify = null;
    }

    /* 필드 구성 **********************************************************************************************************************************/

    /***
     * 객체를 받고 타입을 체크하여 Setter 를 통해 Body 설정해주는 제너릭 메서드
     * @param bodyObject OFFLINE_KEY_MESSAGE_TYPE 클래스
     * @return 성공여부
     * @param <T> OFFLINE_KEY_MESSAGE_TYPE 클래스
     */
    public <T> boolean SetBody(T bodyObject)
    {
        if (bodyObject instanceof ReplaceAllKeys)
        {
            this.ReplaceAllKeys = (ReplaceAllKeys) bodyObject;
        }
        else if (bodyObject instanceof DeleteAllKeys)
        {
            this.DeleteAllKeys = (DeleteAllKeys) bodyObject;
        }
        else if (bodyObject instanceof AddAuthenticationKey)
        {
            this.AddAuthenticationKey = (AddAuthenticationKey) bodyObject;
        }
        else if (bodyObject instanceof DeleteKey)
        {
            this.DeleteKey = (DeleteKey) bodyObject;
        }
        else if (bodyObject instanceof ReplaceEtcsEntities)
        {
            this.ReplaceEtcsEntities = (ReplaceEtcsEntities) bodyObject;
        }
        else if (bodyObject instanceof UpdateKeyValidityPeriod)
        {
            this.UpdateKeyValidityPeriod = (UpdateKeyValidityPeriod) bodyObject;
        }
        else if (bodyObject instanceof InstallTransportKey)
        {
            this.InstallTransportKey = (InstallTransportKey) bodyObject;
        }
        else if (bodyObject instanceof ResponseNotify)
        {
            this.ResponseNotify = (ResponseNotify) bodyObject;
        }
        else
        {
            return false;
        }

        WriteFiledSetLog();
        return true;
    }

    void OfflineHeader(byte[] length, byte version, EtcsInfo receiver, EtcsInfo sender, byte[] transaction, byte[] sequence, byte authAlgo, byte[] serial, byte msgType)
    {
        this.Header = new OfflineHeader(length, version, receiver, sender, transaction, sequence, authAlgo, serial, msgType);
    }

    void AddAuthenticationKey(OfflineKeyStruct[] keyStructs, byte[] cbcMac)
    {
        InitInstanceFiledValues(false);
        Header.SetMsgType(OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_ADD_AUTHENTICATION_KEY);
        this.AddAuthenticationKey = new AddAuthenticationKey(keyStructs,cbcMac);
    }

    void DeleteAllKeys(byte keyType, byte[] cbcMac)
    {
        InitInstanceFiledValues(false);
        Header.SetMsgType(OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_DELETE_ALL_KEYS);
        this.DeleteAllKeys = new DeleteAllKeys(keyType, cbcMac);
    }

    void DeleteKey(EtcsInfo KmEtcsIdExp, byte[] sNum, byte[] cbcMac)
    {
        InitInstanceFiledValues(false);
        Header.SetMsgType(OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_DELETE_KEY);
        this.DeleteKey = new DeleteKey(KmEtcsIdExp, sNum, cbcMac);
    }

    void InstallTransportKey(byte length, byte[] serialNumber, byte[] ktrans, byte[] cbcMac)
    {
        InitInstanceFiledValues(false);
        Header.SetMsgType(OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_INSTALL_TRANSPORT_KEY);
        this.InstallTransportKey = new InstallTransportKey(length, serialNumber, ktrans, cbcMac);
    }

    void ReplaceAllKeys(byte eAlgo, byte[] kNum, OfflineKeyStruct[] KeyStruct, byte[] cbcMac)
    {
        InitInstanceFiledValues(false);
        Header.SetMsgType(OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_REPLACE_ALL_KEYS);
        this.ReplaceAllKeys = new ReplaceAllKeys(eAlgo, kNum, KeyStruct, cbcMac);
    }

    void ReplaceEtcsEntities(EtcsInfo KmEtcsIdExp, byte[] serialNumber, byte[] peerNum, EtcsInfo[] EtcsIdExpPeer, byte[] cbcMac)
    {
        InitInstanceFiledValues(false);
        Header.SetMsgType(OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_REPLACE_ETCS_ENTITIES);
        this.ReplaceEtcsEntities = new ReplaceEtcsEntities(KmEtcsIdExp, serialNumber, peerNum, EtcsIdExpPeer, cbcMac);
    }

    void ResponseNotify(byte result, byte length, byte[] text, byte[] sequenceNumber, byte[] cbcMac)
    {
        InitInstanceFiledValues(false);
        Header.SetMsgType(OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_RESPONSE_NOTIFY);
        this.ResponseNotify = new ResponseNotify(result, length, text, sequenceNumber, cbcMac);
    }

    void UpdateKeyValidityPeriod(EtcsInfo kmEtcsIdExp, byte[] serialNumber, ValidPeriod validPeriod, byte[] cbcMac)
    {
        InitInstanceFiledValues(false);
        Header.SetMsgType(OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_RESPONSE_NOTIFY);
        this.UpdateKeyValidityPeriod = new UpdateKeyValidityPeriod(kmEtcsIdExp, serialNumber, validPeriod, cbcMac);
    }

    public OfflineHeader GetHeader()
    {
        return Header;
    }

    public void SetHeader(OfflineHeader header)
    {
        Header = header;
    }

    public ReplaceAllKeys GetReplaceAllKeys()
    {
        return ReplaceAllKeys;
    }

    public void SetReplaceAllKeys(ReplaceAllKeys replaceAllKeys) {
        InitInstanceFiledValues(false);
        if(Header != null)
        {
            Header.SetMsgType(OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_REPLACE_ALL_KEYS);
        }
        ReplaceAllKeys = replaceAllKeys;
    }

    public DeleteAllKeys getDeleteAllKeys() {
        return DeleteAllKeys;
    }

    public void SetDeleteAllKeys(DeleteAllKeys deleteAllKeys) {
        InitInstanceFiledValues(false);
        if(Header != null)
        {
            Header.SetMsgType(OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_DELETE_ALL_KEYS);
        }
        DeleteAllKeys = deleteAllKeys;
    }

    public AddAuthenticationKey GetAddAuthenticationKey()
    {
        return AddAuthenticationKey;
    }

    public void SetAddAuthenticationKey(AddAuthenticationKey addAuthenticationKey) {
        InitInstanceFiledValues(false);
        if(Header != null)
        {
            Header.SetMsgType(OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_ADD_AUTHENTICATION_KEY);
        }
        AddAuthenticationKey = addAuthenticationKey;
    }

    public DeleteKey GetDeleteKey()
    {
        return DeleteKey;
    }

    public void SetDeleteKey(DeleteKey deleteKey)
    {
        InitInstanceFiledValues(false);
        if(Header != null)
        {
            Header.SetMsgType(OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_DELETE_KEY);
        }
        DeleteKey = deleteKey;
    }

    public ReplaceEtcsEntities GetReplaceEtcsEntities()
    {
        return ReplaceEtcsEntities;
    }

    public void SetReplaceEtcsEntities(ReplaceEtcsEntities replaceEtcsEntities) {
        InitInstanceFiledValues(false);
        if(Header != null)
        {
            Header.SetMsgType(OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_REPLACE_ETCS_ENTITIES);
        }
        ReplaceEtcsEntities = replaceEtcsEntities;
    }

    public UpdateKeyValidityPeriod GetUpdateKeyValidityPeriod()
    {
        return UpdateKeyValidityPeriod;
    }

    public void SetUpdateKeyValidityPeriod(UpdateKeyValidityPeriod updateKeyValidityPeriod)
    {
        InitInstanceFiledValues(false);
        if(Header != null)
        {
            Header.SetMsgType(OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_UPDATE_KEY_VALIDITY_PERIOD);
        }
        UpdateKeyValidityPeriod = updateKeyValidityPeriod;
    }

    public InstallTransportKey GetInstallTransportKey()
    {
        return InstallTransportKey;
    }

    public void SetInstallTransportKey(InstallTransportKey installTransportKey)
    {
        InitInstanceFiledValues(false);
        if(Header != null)
        {
            Header.SetMsgType(OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_INSTALL_TRANSPORT_KEY);
        }
        InstallTransportKey = installTransportKey;
    }

    public ResponseNotify GetResponseNotify()
    {
        return ResponseNotify;
    }

    public void SetResponseNotify(ResponseNotify responseNotify)
    {
        InitInstanceFiledValues(false);
        if(Header != null)
        {
            Header.SetMsgType(OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_RESPONSE_NOTIFY);
        }
        ResponseNotify = responseNotify;
    }
}
