package Message;

import Message.constant.Offline.*;
import Message.constant.Online.*;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.GeneralSecurityException;
import java.util.Arrays;


import singleton.Logger;

public class CodecUtil
{
    public final byte ERROR_BYTE = (byte)0XCD; /* CD(Collision Detection) */
    public final int ERROR_CODE = -1;

    /**
     * Calculate the DES CBC MAC using the standard cipher algorithms
     * @param ktrans 24bytes Ktrans data
     * @param data 헤더부터 CBC 제외한 나머지 패킷
     * @return cbcMac
     * #TODO : MAC 체크 적용
     */
    public byte[] CalculateCbcMac(byte[] ktrans, byte[] data) {
        byte[] cbcMac = null;

        try
        {
            SecretKeySpec skeySpec = new SecretKeySpec(ktrans, "DES");
            Cipher cbcDES = Cipher.getInstance("DES/CBC/ZeroBytePadding");
            cbcDES.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(new byte[8]));
            cbcMac = cbcDES.doFinal(data);
        }
        catch (GeneralSecurityException e)
        {
            e.printStackTrace();
        }

        return cbcMac;
    }

    /**
     * 정수를 바이트배열로 변환
     * @param n 정수
     * @param nByteSize 반환시킬 바이트 배열 사이즈
     * @return 변환된 바이트 배열
     */
    public byte[] IntegerToByteArray(int n, int nByteSize)
    {
        byte[] bBuffer = new byte[nByteSize];

        for(int nIntegerByteIdx = 0; nIntegerByteIdx < nByteSize; nIntegerByteIdx++)
        {
            bBuffer[nIntegerByteIdx] = (byte) (n >> (8 * nIntegerByteIdx));
        }
        /* 순서대로 집어넣고 언디언 뒤집으면 직렬화 시 문제없는 바이트배열로 변경됨 */
        return ReverseEndian(bBuffer);
    }

    /**
     * 발생한 예외의 스택 트레이스를 문자열로 반환
     * * 문자열로 출력하는 이유는 오류 스트림이 버퍼링되어 늦게 출력되는 경우가 생기기때문
     * @param throwable 스텍 트레이스
     * @return 스텍 트레이스 문자열
     */
    private String GetStackTrace(Throwable throwable)
    {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        throwable.printStackTrace(pw);
        return sw.toString();
    }

    /**
     * 이 메서드를 통해 Codec 로그처리 로직을 중앙에서 관리
     * TODO : LOG 작성하는 메서드 - 방식 정해지면 맞춰서 변경
     */
    public void WriteErrorLog(String logMessage)
    {
        final String RED = "\033[0;31m";      // 빨간색
        final String RESET = "\033[0m";              // 리셋 (기본 색상으로 돌아가기)

        Logger logger = Logger.GetInstance();
        logger.Write(logMessage,Logger.LOG_TYPE_CODEC);
        /* Add timeStamp and save log */
        System.out.print(RED + logMessage + RESET);

    }

    public void WriteLog(String logMessage)
    {
        final String CYAN = "\033[0;36m";    // 청록색
        final String RESET = "\033[0m";      // 리셋 (기본 색상으로 돌아가기)
        /* Add timeStamp and save log */
        Logger logger = Logger.GetInstance();
        logger.Write(logMessage,Logger.LOG_TYPE_CODEC);
    }

    /**
     * 바이트배열 로그메시지 처리
     * @param bArray 에러가 발생한 바이트 어레이
     */
    public void WriteErrorLog(byte[] bArray)
    {
        StringBuilder strByteArray = new StringBuilder();

        for(byte c : bArray)
        {
            strByteArray.append(String.format("%02X ", c));
        }

        String strResult = "ErrorPacket : " + strByteArray.toString();
        System.out.println(strResult);
        WriteErrorLog(strResult);
    }

    /***
     * Exception handling process
     * @param exception all type exception
     * <p>
     * *In case of NullPointerException, an information message is sent and the main process terminates.
     */
    public void IsExceptionPrintingAndWriteLog(Exception exception)
    {
        WriteErrorLog( GetStackTrace(exception) );

//        if (exception instanceof NullPointerException)
//        {
//            /* In case of NullPointerException, an information message is sent and the main process terminates. */
//            throw new RuntimeException("Action is required after confirming that a Null Point error has occurred.");
//        }
    }

    public int GetObjectLastIndex(int objectSize)
    {
        return objectSize - 1;
    }

    /***
     * convert hex String to byte array
     * @param s hex String
     * @return byte array
     */
    public byte[] HexStringToByteArray(String s)
    {
        // 공백 무시
        s = s.replace(" ","");
        // 0x무시
        s = s.replace("0x","");
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
        {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    /***
     * @param peer_num Length : 0 ~ 4
     * @return byte To int
     */
    public int ConvertByteArrayToInt(byte[] peer_num)
    {
        if(peer_num.length > 4 ||  peer_num.length == 0)
        {
            return ERROR_CODE;
        }

        int nResult = 0;
        // 배열의 첫 번째 요소부터 마지막 요소까지 반복
        for (int i = 0; i < peer_num.length; i++)
        {
            nResult |= (peer_num[i] & 0xFF) << (8 * (peer_num.length - 1 - i));
        }
        return nResult;
    }

    /**
     * Extracts a subarray from the given target array starting from index nStart to index nEnd (inclusive).
     *
     * @param target The original byte array from which the subarray is extracted.
     * @param nStart The starting index (inclusive) for the extraction.
     * @param nEnd The ending index (inclusive) for the extraction.
     * @return A new byte array containing the elements from the specified range in the target array.
     * @throws IllegalArgumentException if nStart or nEnd are out of bounds, or if nStart is greater than nEnd.
     */
    public byte[] SeparationByteArray(byte[] target, int nStart, int nEnd)
    {
        // Validate indices
        if (nStart < 0 || nEnd >= target.length || nStart > nEnd)
        {
            throw new IllegalArgumentException("Invalid start or end index.");
        }

        int nBufferLength = (nEnd + 1) - nStart;
        byte[] buffer = new byte[nBufferLength];
        System.arraycopy(target, nStart, buffer, 0, nBufferLength);

        return buffer;
    }

    /***
     * @param target target byte array
     * @param addedPacket added byte array
     * @return byteArray : [target + addedPacket]
     */
    public byte[] AddPacket(byte[] target, byte[] addedPacket)
    {
        try(ByteArrayOutputStream outputStream = new ByteArrayOutputStream())
        {
            outputStream.write(target);
            outputStream.write(addedPacket);

            return outputStream.toByteArray();
        }
        catch (IOException e)
        {
            IsExceptionPrintingAndWriteLog(e);
            return MakeErrorPacket(target.length+ addedPacket.length);
        }
    }

    /**
     * Serializes multiple byte arrays into a single byte array.
     * @param byteArrays Variable number of byte arrays to serialize.
     * @return The serialized byte array.
     * @throws IOException If an I/O error occurs.
     */
    public byte[] SerializeMultipleByteArrays(byte[]... byteArrays) throws IOException
    {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DataOutputStream dos = new DataOutputStream(baos))
        {
            for (byte[] byteArray : byteArrays)
            {
                dos.write(byteArray);
            }
            return baos.toByteArray();
        }
    }

    /**
     * Reverses the byte order of a byte array.
     * This method swaps the endianness of the byte array.
     * @param bytes The byte array to reverse.
     * @return The byte array with reversed byte order.
     */
    public byte[] ReverseEndian(byte[] bytes)
    {
        byte[] buffer = new byte[bytes.length];
        int nBufferIdx = 0;
        for (int idx = bytes.length - 1; idx >= 0; idx--) {
            buffer[nBufferIdx++] = bytes[idx];
        }

        return buffer;
    }

    /**
     * @param nByteSize Making Buffer Length
     * @return Error bufferArray to fill(0xff)
     */
    public byte[] MakeErrorPacket(int nByteSize)
    {
        byte[] errorBuffer = new byte[nByteSize];
        Arrays.fill(errorBuffer, ERROR_BYTE);
        return errorBuffer;
    }

    /**
     * Sets the target buffer with the provided buffer if they have the same length.
     * If the lengths are different, returns an error buffer of the same length as the target buffer.
     *
     * @param targetBuffer The target byte array to compare length with.
     * @param buffer The byte array to set as the new buffer if lengths match.
     * @return The provided buffer if lengths match, otherwise an error buffer of the same length as the target buffer.
     */
    public byte[] SafeSetByteArray(byte[] targetBuffer, byte[] buffer)
    {
        /* 기존 값의 크기를 변화시키지 않는 경우에만 바이트 배열 적용 */
        return targetBuffer.length == buffer.length ? buffer : MakeErrorPacket(targetBuffer.length);
    }





    /* Const Value 관련 메서드************************************************************************************************************************/
    /* OFFLINE_KM_MESSAGE 메시지 체크 */
    public boolean CheckOfflineKmMsgType(int msgType)
    {
        return switch (msgType)
        {
            case OFFLINE_KM_MESSAGE.KMAC_EXCHANGE,
                    OFFLINE_KM_MESSAGE.KMAC_DELETION,
                    OFFLINE_KM_MESSAGE.KMAC_UPDATE,
                    OFFLINE_KM_MESSAGE.CONF_KMAC_EXCHANGE,
                    OFFLINE_KM_MESSAGE.CONF_KMAC_DELETION,
                    OFFLINE_KM_MESSAGE.CONF_KMAC_UPDATE,
                    OFFLINE_KM_MESSAGE.KMAC_NEGACK
                    -> true;
            default -> false;
        };
    }

    /* OFFLINE_KM_MESSAGE 메시지 문자열 */
    public String GetOfflineKmMsgTypeToStringName(int msgType)
    {
        return switch (msgType)
        {
            case OFFLINE_KM_MESSAGE.KMAC_EXCHANGE -> "KMAC_EXCHANGE";
            case OFFLINE_KM_MESSAGE.KMAC_DELETION -> "KMAC_DELETION";
            case OFFLINE_KM_MESSAGE.KMAC_UPDATE -> "KMAC_UPDATE";
            case OFFLINE_KM_MESSAGE.CONF_KMAC_EXCHANGE -> "CONF_KMAC_EXCHANGE";
            case OFFLINE_KM_MESSAGE.CONF_KMAC_DELETION -> "CONF_KMAC_DELETION";
            case OFFLINE_KM_MESSAGE.CONF_KMAC_UPDATE -> "CONF_KMAC_UPDATE";
            case OFFLINE_KM_MESSAGE.KMAC_NEGACK -> "KMAC_NEGACK";
            default -> "UNKNOWN_MESSAGE_TYPE";
        };
    }


    public boolean CheckOfflineKeyMsgAuthAlgo(int msgType)
    {
        return switch (msgType)
        {
            case KEY_MESSAGE_AUTH_ALGO.CRYPT_3DES_ECB,
                    KEY_MESSAGE_AUTH_ALGO.RESERVED,
                    KEY_MESSAGE_AUTH_ALGO.NDEFINED -> true;
            default -> false;
        };
    }


    public boolean CheckOfflineKeyMsgType(int msgType)
    {
        return switch (msgType)
        {
            case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_REPLACE_ALL_KEYS,
                    OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_DELETE_ALL_KEYS,
                    OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_ADD_AUTHENTICATION_KEY,
                    OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_DELETE_KEY,
                    OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_REPLACE_ETCS_ENTITIES,
                    OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_UPDATE_KEY_VALIDITY_PERIOD,
                    OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_INSTALL_TRANSPORT_KEY,
                    OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_RESPONSE_NOTIFY -> true;
            default -> false;
        };
    }

    public String GetOfflineKeyMsgTypeToStringName(int msgType)
    {
        return switch (msgType)
        {
            case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_REPLACE_ALL_KEYS -> "KEY_MESSAGE_REPLACE_ALL_KEYS";
            case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_DELETE_ALL_KEYS -> "KEY_MESSAGE_DELETE_ALL_KEYS";
            case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_ADD_AUTHENTICATION_KEY -> "KEY_MESSAGE_ADD_AUTHENTICATION_KEY";
            case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_DELETE_KEY -> "KEY_MESSAGE_DELETE_KEY";
            case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_REPLACE_ETCS_ENTITIES -> "KEY_MESSAGE_REPLACE_ETCS_ENTITIES";
            case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_UPDATE_KEY_VALIDITY_PERIOD -> "KEY_MESSAGE_UPDATE_KEY_VALIDITY_PERIOD";
            case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_INSTALL_TRANSPORT_KEY -> "KEY_MESSAGE_INSTALL_TRANSPORT_KEY";
            case OFFLINE_KEY_MESSAGE_TYPE.KEY_MESSAGE_RESPONSE_NOTIFY -> "KEY_MESSAGE_RESPONSE_NOTIFY";
            default -> "UNKNOWN_MESSAGE_TYPE";
        };
    }

    public boolean CheckOfflineKeyResultCode(int nResultCode)
    {
        return switch (nResultCode)
        {
            case OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_SUCCESSFULLY_PROCESSED,
                    OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_RECEIVED_SUCCESSFULLY,
                    OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_AUTHENTICATION_OF_MAC_COD_HAS_FAILED,
                    OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_AUTHENTICATION_ALGORITHM_NOT_IMPLEMENTED,
                    OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_TRANSPORT_KEY_NOT_FOUND,
                    OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_DECRYPTION_ALGORITHM_NOT_IMPLEMENTATION,
                    OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_KEY_NOT_KNOW,
                    OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_MAXIMUM_NUMBER_OF_KEYS_EXCEEDED,
                    OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_MAXIMUM_NUMBER_OF_ETCS_ENTITIES_EXCEEDED,
                    OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_KEY_ALREADY_DEFINED_IN_THE_ETCS_ENTITY,
                    OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_NOT_SUPPORTED,
                    OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_INCONSISTENCY_DETECTED_IN_THE_RECEIVED_REQUEST,
                    OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_MESSAGE_LENGTH_ERROR,
                    OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_NOT_ISSUED_BY_THE_HOME_KMC,
                    OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_SENT_TO_WRONG_ETCS_ENTITY,
                    OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_KEY_CORRUPTED,
                    OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_UNRECOVERABLE_KEY_STORE_ERROR,
                    OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_INTERFACE_VERSION_NOT_SUPPORTED,
                    OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_ETC_ERROR -> true;
            default -> false;
        };
    }

    public String GetOfflineKeyResultCodeToStringName(int nResultCode)
    {
        return switch (nResultCode)
        {
            case OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_SUCCESSFULLY_PROCESSED -> "RESPONSE_RESULT_REQUEST_SUCCESSFULLY_PROCESSED";
            case OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_RECEIVED_SUCCESSFULLY -> "RESPONSE_RESULT_REQUEST_RECEIVED_SUCCESSFULLY";
            case OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_AUTHENTICATION_OF_MAC_COD_HAS_FAILED -> "RESPONSE_RESULT_AUTHENTICATION_OF_MAC_COD_HAS_FAILED";
            case OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_AUTHENTICATION_ALGORITHM_NOT_IMPLEMENTED -> "RESPONSE_RESULT_AUTHENTICATION_ALGORITHM_NOT_IMPLEMENTED";
            case OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_TRANSPORT_KEY_NOT_FOUND -> "RESPONSE_RESULT_TRANSPORT_KEY_NOT_FOUND";
            case OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_DECRYPTION_ALGORITHM_NOT_IMPLEMENTATION -> "RESPONSE_RESULT_DECRYPTION_ALGORITHM_NOT_IMPLEMENTATION";
            case OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_KEY_NOT_KNOW -> "RESPONSE_RESULT_KEY_NOT_KNOW";
            case OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_MAXIMUM_NUMBER_OF_KEYS_EXCEEDED -> "RESPONSE_RESULT_MAXIMUM_NUMBER_OF_KEYS_EXCEEDED";
            case OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_MAXIMUM_NUMBER_OF_ETCS_ENTITIES_EXCEEDED -> "RESPONSE_RESULT_MAXIMUM_NUMBER_OF_ETCS_ENTITIES_EXCEEDED";
            case OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_KEY_ALREADY_DEFINED_IN_THE_ETCS_ENTITY -> "RESPONSE_RESULT_KEY_ALREADY_DEFINED_IN_THE_ETCS_ENTITY";
            case OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_NOT_SUPPORTED -> "RESPONSE_RESULT_REQUEST_NOT_SUPPORTED";
            case OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_INCONSISTENCY_DETECTED_IN_THE_RECEIVED_REQUEST -> "RESPONSE_RESULT_INCONSISTENCY_DETECTED_IN_THE_RECEIVED_REQUEST";
            case OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_MESSAGE_LENGTH_ERROR -> "RESPONSE_RESULT_MESSAGE_LENGTH_ERROR";
            case OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_NOT_ISSUED_BY_THE_HOME_KMC -> "RESPONSE_RESULT_REQUEST_NOT_ISSUED_BY_THE_HOME_KMC";
            case OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_REQUEST_SENT_TO_WRONG_ETCS_ENTITY -> "RESPONSE_RESULT_REQUEST_SENT_TO_WRONG_ETCS_ENTITY";
            case OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_KEY_CORRUPTED -> "RESPONSE_RESULT_KEY_CORRUPTED";
            case OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_UNRECOVERABLE_KEY_STORE_ERROR -> "RESPONSE_RESULT_UNRECOVERABLE_KEY_STORE_ERROR";
            case OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_INTERFACE_VERSION_NOT_SUPPORTED -> "RESPONSE_RESULT_INTERFACE_VERSION_NOT_SUPPORTED";
            case OFFLINE_RESPONSE_NOTIFY_MSG_RESULT_CODE.RESPONSE_RESULT_ETC_ERROR -> "RESPONSE_RESULT_ETC_ERROR";
            default -> "UNKNOWN_RESULT_CODE";
        };
    }

    public static boolean CheckOnlineKeyMsgType(int msgType)
    {
        return switch (msgType)
        {
            case ONLINE_KEY_MESSAGE_TYPE.CMD_ADD_KEYS,
                    ONLINE_KEY_MESSAGE_TYPE.CMD_DELETE_KEYS,
                    ONLINE_KEY_MESSAGE_TYPE.CMD_DELETE_ALL_KEYS,
                    ONLINE_KEY_MESSAGE_TYPE.CMD_UPDATE_KEY_VALIDITIES,
                    ONLINE_KEY_MESSAGE_TYPE.CMD_UPDATE_KEY_ENTITIES,
                    ONLINE_KEY_MESSAGE_TYPE.CMD_REQUEST_KEY_OPERATION,
                    ONLINE_KEY_MESSAGE_TYPE.INQ_REQUEST_KEY_DB_CHECKSUM,
                    ONLINE_KEY_MESSAGE_TYPE.NOTIF_KEY_UPDATE_STATUS,
                    ONLINE_KEY_MESSAGE_TYPE.NOTIF_ACK_KEY_UPDATE_STATUS,
                    ONLINE_KEY_MESSAGE_TYPE.NOTIF_SESSION_INIT,
                    ONLINE_KEY_MESSAGE_TYPE.NOTIF_END_OF_UPDATE,
                    ONLINE_KEY_MESSAGE_TYPE.NOTIF_RESPONSE,
                    ONLINE_KEY_MESSAGE_TYPE.NOTIF_KEY_OPERATION_REQ_RCVD,
                    ONLINE_KEY_MESSAGE_TYPE.NOTIF_KEY_DB_CHECKSUM,
                    ONLINE_KEY_MESSAGE_TYPE.NOTIF_DEVICE_INFO -> true;
            default -> false;
        };
    }

    public static String GetOnlineKeyMsgTypeToStringName(int msgType)
    {
        return switch (msgType)
        {
            case ONLINE_KEY_MESSAGE_TYPE.CMD_ADD_KEYS -> "CMD_ADD_KEYS";
            case ONLINE_KEY_MESSAGE_TYPE.CMD_DELETE_KEYS -> "CMD_DELETE_KEYS";
            case ONLINE_KEY_MESSAGE_TYPE.CMD_DELETE_ALL_KEYS -> "CMD_DELETE_ALL_KEYS";
            case ONLINE_KEY_MESSAGE_TYPE.CMD_UPDATE_KEY_VALIDITIES -> "CMD_UPDATE_KEY_VALIDITIES";
            case ONLINE_KEY_MESSAGE_TYPE.CMD_UPDATE_KEY_ENTITIES -> "CMD_UPDATE_KEY_ENTITIES";
            case ONLINE_KEY_MESSAGE_TYPE.CMD_REQUEST_KEY_OPERATION -> "CMD_REQUEST_KEY_OPERATION";
            case ONLINE_KEY_MESSAGE_TYPE.INQ_REQUEST_KEY_DB_CHECKSUM -> "INQ_REQUEST_KEY_DB_CHECKSUM";
            case ONLINE_KEY_MESSAGE_TYPE.NOTIF_KEY_UPDATE_STATUS -> "NOTIF_KEY_UPDATE_STATUS";
            case ONLINE_KEY_MESSAGE_TYPE.NOTIF_ACK_KEY_UPDATE_STATUS -> "NOTIF_ACK_KEY_UPDATE_STATUS";
            case ONLINE_KEY_MESSAGE_TYPE.NOTIF_SESSION_INIT -> "NOTIF_SESSION_INIT";
            case ONLINE_KEY_MESSAGE_TYPE.NOTIF_END_OF_UPDATE -> "NOTIF_END_OF_UPDATE";
            case ONLINE_KEY_MESSAGE_TYPE.NOTIF_RESPONSE -> "NOTIF_RESPONSE";
            case ONLINE_KEY_MESSAGE_TYPE.NOTIF_KEY_OPERATION_REQ_RCVD -> "NOTIF_KEY_OPERATION_REQ_RCVD";
            case ONLINE_KEY_MESSAGE_TYPE.NOTIF_KEY_DB_CHECKSUM -> "NOTIF_KEY_DB_CHECKSUM";
            case ONLINE_KEY_MESSAGE_TYPE.NOTIF_DEVICE_INFO -> "NOTIF_DEVICE_INFO";
            default -> "UNKNOWN_MESSAGE_TYPE";
        };
    }

    public boolean CheckOnlineKeyResponseCode(int responseCode)
    {
        return switch (responseCode)
        {
            case ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_REQUEST_SUCCESSFULLY_PROCESSED,
                    ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_REQUEST_NOT_SUPPORTED,
                    ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_MASSAGE_LENGTH_ERROR,
                    ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_NO_MATCH_EXPECTED_KMC_ETCSIDEXP,
                    ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_NO_MATCH_EXPECTED_MY_ETCSIDEXP,
                    ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_UNSUPPORTED_IF_VERSION,
                    ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_UNRECOVERABLE_KEY_DATABASE,
                    ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_FAIL_REQUEST_PROCESSING,
                    ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_CHECKSUM_MISMATCH,
                    ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_SEQUENCE_NUMBER_MISMATCH,
                    ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_TRANSACTION_NUMBER_MISMATCH,
                    ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_FORMAT_ERROR,
                    ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_OTHER_ERROR -> true;
            default -> false;
        };
    }

    public String GetOnlineKeyResponseCodeToStringName(int responseCode)
    {
        return switch (responseCode)
        {
            case ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_REQUEST_SUCCESSFULLY_PROCESSED -> "RESPONSE_CODE_REQUEST_SUCCESSFULLY_PROCESSED";
            case ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_REQUEST_NOT_SUPPORTED -> "RESPONSE_CODE_REQUEST_NOT_SUPPORTED";
            case ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_MASSAGE_LENGTH_ERROR -> "RESPONSE_CODE_MASSAGE_LENGTH_ERROR";
            case ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_NO_MATCH_EXPECTED_KMC_ETCSIDEXP -> "RESPONSE_CODE_NO_MATCH_EXPECTED_KMC_ETCSIDEXP";
            case ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_NO_MATCH_EXPECTED_MY_ETCSIDEXP -> "RESPONSE_CODE_NO_MATCH_EXPECTED_MY_ETCSIDEXP";
            case ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_UNSUPPORTED_IF_VERSION -> "RESPONSE_CODE_UNSUPPORTED_IF_VERSION";
            case ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_UNRECOVERABLE_KEY_DATABASE -> "RESPONSE_CODE_UNRECOVERABLE_KEY_DATABASE";
            case ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_FAIL_REQUEST_PROCESSING -> "RESPONSE_CODE_FAIL_REQUEST_PROCESSING";
            case ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_CHECKSUM_MISMATCH -> "RESPONSE_CODE_CHECKSUM_MISMATCH";
            case ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_SEQUENCE_NUMBER_MISMATCH -> "RESPONSE_CODE_SEQUENCE_NUMBER_MISMATCH";
            case ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_TRANSACTION_NUMBER_MISMATCH -> "RESPONSE_CODE_TRANSACTION_NUMBER_MISMATCH";
            case ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_FORMAT_ERROR -> "RESPONSE_CODE_FORMAT_ERROR";
            case ONLINE_NOTIFY_RESPONSE_RESULT_CODE.RESPONSE_CODE_OTHER_ERROR -> "RESPONSE_CODE_OTHER_ERROR";
            default -> "UNKNOWN_RESPONSE_CODE";
        };
    }


    public boolean CheckOnlineKeyNotificationResultCode(int resultCode)
    {
        return switch (resultCode)
        {
            case RESPONSE_NOTIFICATION_RESULT_CODE.NOTIFICATION_RESULT_REQUEST_SUCCESSFULLY_PROCESSED,
                    RESPONSE_NOTIFICATION_RESULT_CODE.NOTIFICATION_RESULT_UNKNOWN_KEY,
                    RESPONSE_NOTIFICATION_RESULT_CODE.NOTIFICATION_RESULT_MAX_NUM_OF_KEY_EXCEEDED,
                    RESPONSE_NOTIFICATION_RESULT_CODE.NOTIFICATION_RESULT_ALREADY_INSTALLED,
                    RESPONSE_NOTIFICATION_RESULT_CODE.NOTIFICATION_RESULT_KEY_CORRUPTED,
                    RESPONSE_NOTIFICATION_RESULT_CODE.NOTIFICATION_RESULT_RECIPIENT_ETCSID_MISMATCH,
                    RESPONSE_NOTIFICATION_RESULT_CODE.NOTIFICATION_RESULT_OTHER_ERROR -> true;
            default -> false;
        };
    }

    public String GetOnlineKeyNotificationResultCodeToStringName(int resultCode)
    {
        return switch (resultCode)
        {
            case RESPONSE_NOTIFICATION_RESULT_CODE.NOTIFICATION_RESULT_REQUEST_SUCCESSFULLY_PROCESSED -> "NOTIFICATION_RESULT_REQUEST_SUCCESSFULLY_PROCESSED";
            case RESPONSE_NOTIFICATION_RESULT_CODE.NOTIFICATION_RESULT_UNKNOWN_KEY -> "NOTIFICATION_RESULT_UNKNOWN_KEY";
            case RESPONSE_NOTIFICATION_RESULT_CODE.NOTIFICATION_RESULT_MAX_NUM_OF_KEY_EXCEEDED -> "NOTIFICATION_RESULT_MAX_NUM_OF_KEY_EXCEEDED";
            case RESPONSE_NOTIFICATION_RESULT_CODE.NOTIFICATION_RESULT_ALREADY_INSTALLED -> "NOTIFICATION_RESULT_ALREADY_INSTALLED";
            case RESPONSE_NOTIFICATION_RESULT_CODE.NOTIFICATION_RESULT_KEY_CORRUPTED -> "NOTIFICATION_RESULT_KEY_CORRUPTED";
            case RESPONSE_NOTIFICATION_RESULT_CODE.NOTIFICATION_RESULT_RECIPIENT_ETCSID_MISMATCH -> "NOTIFICATION_RESULT_RECIPIENT_ETCSID_MISMATCH";
            case RESPONSE_NOTIFICATION_RESULT_CODE.NOTIFICATION_RESULT_OTHER_ERROR -> "NOTIFICATION_RESULT_OTHER_ERROR";
            default -> "UNKNOWN_NOTIFICATION_RESULT_CODE";
        };
    }
}