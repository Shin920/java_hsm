package codec.offlineEntity;

import Message.CodecUtil;
import Message.offline.entity.*;
import Message.offline.entity.sub.*;
import Message.constant.Common.*;
import Message.constant.Offline.*;
public class OfflineKeyMsgDecoder extends CodecUtil
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

    private int resultCode = OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_SUCCESSFULLY_PROCESSED;

    /* 생성자 ********************************************************************************************************************/

    public OfflineKeyMsgDecoder(){}

    /**
     * Decoder 기본 생성자 * 디코더는 버퍼를 받아 파싱하는 역할만 수행
     * @param bOfflineMessageBuffer Offline Message
     * @throws IllegalArgumentException 파싱 실패 시 발생시키는 예외
     */
    public OfflineKeyMsgDecoder(byte[] bOfflineMessageBuffer) throws IllegalArgumentException
    {
        SetResultCode( DecodeMessage(bOfflineMessageBuffer) );
        if(GetResultCode() == OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_SUCCESSFULLY_PROCESSED)
        {
            WriteSuccessLog(); /* 성공 시 파싱 내용 로깅 */
        }
        else
        {
            throw new IllegalArgumentException(EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
        }
    }

    /**
     * 헤더와 바디 버퍼를 따로 받아 파싱하는 생성자
     * @param bHeaderBuffer 헤더 메시지
     * @param bBodyBuffer 바디 메시지
     * @throws IllegalArgumentException 파싱 실패 시 발생시키는 예외
     */
    public OfflineKeyMsgDecoder(byte[] bHeaderBuffer, byte[] bBodyBuffer) throws IllegalArgumentException
    {
        SetResultCode( DecodeMessage(bHeaderBuffer, bBodyBuffer) );
        if(GetResultCode() != OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_SUCCESSFULLY_PROCESSED)
        {
            throw new IllegalArgumentException(EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
        }
        else
        {
            WriteSuccessLog();
        }
    }

    /* 클래스 메서드 **************************************************************************************************************/

    /**
     * 헤더와 바디 버퍼를 따로 받아서 클래스 초기화
     * @param bHeaderBuffer 헤더 메시지
     * @param bBodyBuffer 바디 메시지
     * @return OFFLINE_NOTIFY_RESPONSE_RESULT_CODE
     */
    public int DecodeMessage(byte[] bHeaderBuffer, byte[] bBodyBuffer)
    {
        return DecodeMessage( super.AddPacket(bHeaderBuffer, bBodyBuffer) );
    }

    /**
     * 바이트 배열을 통해 구조체 초기화
     * @param bOfflineMessage 메시지 패킷
     * @return OFFLINE_NOTIFY_RESPONSE_RESULT_CODE
     */
    public int DecodeMessage(byte[] bOfflineMessage)
    {
        /* 필드 인스턴스 초기화 */
        InitInstanceFiledValues();

        int nHeaderSize = GetHeader().GetSize();
        int nResultCode = OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_INCONSISTENCY_DETECTED_IN_THE_RECEIVED_REQUEST;
        /* 헤더의 크기값은 고정이므로 시작부터 헤더의 크기까지 자르고, 나머지는 바디값으로 사용 */
        byte[] bHeaderArray = super.SeparationByteArray(bOfflineMessage,0, super.GetObjectLastIndex(nHeaderSize) );
        byte[] bBodyArray = super.SeparationByteArray(bOfflineMessage, nHeaderSize, super.GetObjectLastIndex(bOfflineMessage.length));

        /* 파싱 성공 여부에 따라 리턴값 결정 */
        try
        {
            {
                /*TODO :CBC MAC check*/
            }

            nResultCode = DecodeHeader(bHeaderArray);
            if (nResultCode == OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_SUCCESSFULLY_PROCESSED)
            {
                if(ConvertByteArrayToInt( GetHeader().GetLength() ) != bOfflineMessage.length ) /* 헤더 파싱에 문제가 없다면 길이 검사 */
                {
                    nResultCode = OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_MESSAGE_LENGTH_ERROR; /* 길이 문제 발생 시 에러코드 설정 */
                    throw new IllegalArgumentException("[OfflineMsgDecoder] Packet size does not match length field in header");
                }
            }
            else
            {
                throw new IllegalArgumentException("[OfflineMsgDecoder] Header packet parsing Fail");
            }

            nResultCode = DecodeBody(bBodyArray);
            if (nResultCode != OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_SUCCESSFULLY_PROCESSED)
            {
                throw new IllegalArgumentException("[OfflineMsgDecoder] Body packet parsing Fail");
            }
        }
        catch (IllegalArgumentException e)
        {
            super.IsExceptionPrintingAndWriteLog(e);

        }
        catch (Exception e)
        {
            /* 디코더 메소드에서 정의되지 않은 예외 발생 시 에러코드 설정 */
            nResultCode = OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_ETC_ERROR;
            super.IsExceptionPrintingAndWriteLog(e);
        }
        finally
        {
            return nResultCode;
        }
    }

    /**
     * 헤더 메시지 디코딩
     * @param bHeaderArray 파싱할 버퍼
     * @return 성공여부
     */
    private int DecodeHeader(byte[] bHeaderArray)
    {
        return this.Header.DecodeMessage(bHeaderArray);
    }

    /**
     * 바디 메시지 디코딩
     * @param bBodyArray 파싱할 버퍼
     * @return 성공여부
     */
    private int DecodeBody(byte[] bBodyArray) {
        int nResultCode = OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_SUCCESSFULLY_PROCESSED;
        try
        {
            switch (this.Header.GetMsgType())
            {
                case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_REPLACE_ALL_KEYS ->
                {
                    ReplaceAllKeys = new ReplaceAllKeys();
                    nResultCode = ReplaceAllKeys.DecodeMessage(bBodyArray);
                }
                case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_DELETE_ALL_KEYS ->
                {
                    DeleteAllKeys = new DeleteAllKeys();
                    nResultCode = DeleteAllKeys.DecodeMessage(bBodyArray);
                }
                case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_ADD_AUTHENTICATION_KEY ->
                {
                    AddAuthenticationKey = new AddAuthenticationKey();
                    nResultCode = AddAuthenticationKey.DecodeMessage(bBodyArray);
                }
                case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_DELETE_KEY ->
                {
                    DeleteKey = new DeleteKey();
                    nResultCode = DeleteKey.DecodeMessage(bBodyArray);
                }
                case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_REPLACE_ETCS_ENTITIES ->
                {
                    ReplaceEtcsEntities = new ReplaceEtcsEntities();
                    nResultCode = ReplaceEtcsEntities.DecodeMessage(bBodyArray);
                }
                case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_UPDATE_KEY_VALIDITY_PERIOD ->
                {
                    UpdateKeyValidityPeriod = new UpdateKeyValidityPeriod();
                    nResultCode = UpdateKeyValidityPeriod.DecodeMessage(bBodyArray);
                }
                case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_INSTALL_TRANSPORT_KEY ->
                {
                    InstallTransportKey = new InstallTransportKey();
                    nResultCode = InstallTransportKey.DecodeMessage(bBodyArray);
                }
                case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_RESPONSE_NOTIFY ->
                {
                    ResponseNotify = new ResponseNotify();
                    nResultCode = ResponseNotify.DecodeMessage(bBodyArray);
                }
                default -> {
                    /* 정의되지 않은 메시지 예외처리 */
                    String strException = String.format("[OfflineMsgDecoder] Header MsgType Value does not belong to OFFLINE_KEY_MESSAGE_TYPE. [type value : %d ]",Header.GetMsgType());
                    throw new IllegalArgumentException(strException);
                }
            }
        }
        catch (Exception e)
        {
            if(e instanceof NullPointerException) /* 헤더를 설정하지 않고 바디를 파싱하면 발생 */
            {
                NullPointerException exception = new NullPointerException("[OfflineMsgDecoder] Header is Null");
                exception.setStackTrace(e.getStackTrace());
                super.IsExceptionPrintingAndWriteLog(exception);
            }

            super.IsExceptionPrintingAndWriteLog(e);
            nResultCode = OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_INCONSISTENCY_DETECTED_IN_THE_RECEIVED_REQUEST; /* 실패 결과값 설정 */
        }
        finally
        {
            return nResultCode;
        }
    }

    /**
     * 헤더 타입에 맞춰 생성된 객체를 추적하여 사이즈 추출
     * @return Header Size + Body Size
     */
    public int GetSize()
    {
        int nBufferSize = COMMON_SIZE.EMPTY;
        try
        {
            nBufferSize = Header.GetSize(); /* 초기값은 헤더 사이즈 */
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
                /* 정의되지 않은 메시지 예외처리 */
                default ->
                {
                    String strException = String.format("[OfflineMsgDecoder] Header MsgType Value does not belong to OFFLINE_KEY_MESSAGE_TYPE. [type value : %d ]",Header.GetMsgType());
                    throw new IllegalArgumentException(strException);
                }
            }
        }
        catch (NullPointerException | IllegalArgumentException e)
        {
            super.IsExceptionPrintingAndWriteLog(e);
            nBufferSize = ERROR_CODE; /* 실패 결과값 설정 */
        }
        finally
        {
            return nBufferSize;
        }
    }


    private void WriteSuccessLog()
    {
        String strSuccessMsg = String.format("[OfflineMsgDecoder] Parsing %s message", CheckOfflineKeyMsgType(Header.GetMsgType()));
        WriteLog(strSuccessMsg);
    }

    private void InitInstanceFiledValues()
    {
        Header = new OfflineHeader();
        ReplaceAllKeys = null;
        DeleteAllKeys = null;
        AddAuthenticationKey = null;
        DeleteKey = null;
        ReplaceEtcsEntities = null;
        UpdateKeyValidityPeriod = null;
        InstallTransportKey = null;
        ResponseNotify = null;
    }

    /* getter ************************************************************************************************************/

    public OfflineHeader GetHeader()
    {
        return Header;
    }

    public ReplaceAllKeys GetReplaceAllKeys()
    {
        return ReplaceAllKeys;
    }

    public DeleteAllKeys GetDeleteAllKeys()
    {
        return DeleteAllKeys;
    }

    public AddAuthenticationKey GetAddAuthenticationKey()
    {
        return AddAuthenticationKey;
    }

    public DeleteKey GetDeleteKey()
    {
        return DeleteKey;
    }

    public ReplaceEtcsEntities GetReplaceEtcsEntities()
    {
        return ReplaceEtcsEntities;
    }

    public UpdateKeyValidityPeriod GetUpdateKeyValidityPeriod()
    {
        return UpdateKeyValidityPeriod;
    }

    public InstallTransportKey GetInstallTransportKey()
    {
        return InstallTransportKey;
    }

    public ResponseNotify GetResponseNotify()
    {
        return ResponseNotify;
    }

    public int GetResultCode()
    {
        return resultCode;
    }

    private void SetResultCode(int resultCode)
    {
        this.resultCode = resultCode;
    }
}
