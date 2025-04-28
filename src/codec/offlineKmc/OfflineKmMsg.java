package codec.offlineKmc;

import Message.CodecUtil;
import Message.offline.kmc.*;
import Message.constant.Common.*;
import Message.constant.Offline.*;
/**
 * This is a class that creates KM messages for requests and responses.
 * You can set up the structure through the constructor that takes a byte array as a parameter.
 * <p>
 * When you set the structure to use using a setter, msg_type is automatically set.
 * <p>
 * When you use the setNegackResponse(REQUEST_KM_MESSAGE_OBJECT, reasonCode) method, the corresponding structure is automatically set.
 * <p>
 * If you use the setResponse(REQUEST_KM_MESSAGE_OBJECT) method, the response structure for the request message is automatically set.
 * In some cases, you may need to enter a subtype value.
 */
public class OfflineKmMsg extends CodecUtil
{
    /* Save KM Message type */
    private byte KmMessageType;

    private ConfKmacDeletion ConfKmacDeletion;
    private ConfKmacExchange ConfKmacExchange;
    private ConfKmacUpdate ConfKmacUpdate;
    private KmacDeletion KmacDeletion;
    private KmacExchange KmacExchange;
    private KmacUpdate KmacUpdate;
    private KmacNegack KmacNegack;

    public OfflineKmMsg()
    {
        InitInstanceFiledValues();
    }

    /***
     * Set the structure through byte array parameter values.
     * @param bOfflineKmMessage byte Array
     */
    public OfflineKmMsg(byte[] bOfflineKmMessage) throws IllegalArgumentException
    {
        if(!DecodeMessage(bOfflineKmMessage))
        {
            throw new IllegalArgumentException(EXCEPTION_STRING.EXCEPTION_MESSAGE_VALUE_ERROR);
        }
    }

    /***
     * Set the structure through byte array parameter values.
     * @param bOfflineKmMessage byte Array
     * #TODO : Check Cbc Mac
     */
    public boolean DecodeMessage(byte[] bOfflineKmMessage)
    {
        InitInstanceFiledValues();
        boolean bResult = false;
        try
        {
            this.KmMessageType = bOfflineKmMessage[COMMON_SIZE.ETCS_MESSAGE_TYPE_IDX];
            switch(this.KmMessageType)
            {
                case OFFLINE_KM_MESSAGE.CONF_KMAC_DELETION ->
                {
                    ConfKmacDeletion = new ConfKmacDeletion(bOfflineKmMessage);
                }
                case OFFLINE_KM_MESSAGE.KMAC_EXCHANGE ->
                {
                    KmacExchange = new KmacExchange(bOfflineKmMessage);
                }
                case OFFLINE_KM_MESSAGE.KMAC_DELETION ->
                {
                    KmacDeletion = new KmacDeletion(bOfflineKmMessage);
                }
                case OFFLINE_KM_MESSAGE.CONF_KMAC_EXCHANGE ->
                {
                    ConfKmacExchange = new ConfKmacExchange(bOfflineKmMessage);
                }
                case OFFLINE_KM_MESSAGE.CONF_KMAC_UPDATE ->
                {
                    ConfKmacUpdate = new ConfKmacUpdate(bOfflineKmMessage);
                }
                case OFFLINE_KM_MESSAGE.KMAC_NEGACK ->
                {
                    KmacNegack = new KmacNegack(bOfflineKmMessage);
                }
                case OFFLINE_KM_MESSAGE.KMAC_UPDATE ->
                {
                    KmacUpdate = new KmacUpdate(bOfflineKmMessage);
                }
                default ->
                {
                    throw new IllegalArgumentException("[OfflineKmMsg] MsgType Value does not belong to OFFLINE_KM_MESSAGE");
                }
            }
            bResult = true;
        }
        catch (NullPointerException e) /* 헤더에서 메시지 타입 필드를 참조할 수 없는 경우 버퍼 에러 */
        {
            Exception exception = e;
            exception = new NullPointerException("[OfflineKmMsg] KM_MESSAGE buffer Error");
            super.IsExceptionPrintingAndWriteLog(exception);
        }
        catch (Exception e)
        {
            super.IsExceptionPrintingAndWriteLog(e);
        }
        finally
        {
            return bResult;
        }
    }

    /**
     * Retrieves the packet based on the message type.
     * <p>
     * This method determines the message type and calls the appropriate method to get the packet.
     * If the message type is not recognized, or if a NullPointerException occurs (indicating that the
     * object was not initialized), an error buffer is returned.
     * </p>
     *
     * @return a byte array containing the packet data, or an error buffer if the message type
     * is unrecognized or if a NullPointerException occurs
     */
    public byte[] EncodeObject(){
        byte[] returnErrorBuffer = new byte[]{ERROR_BYTE};
        try
        {
            switch (this.KmMessageType)
            {
                case OFFLINE_KM_MESSAGE.CONF_KMAC_DELETION ->
                {
                    return ConfKmacDeletion.EncodeObject();
                }
                case OFFLINE_KM_MESSAGE.KMAC_EXCHANGE ->
                {
                    return KmacExchange.EncodeObject();
                }
                case OFFLINE_KM_MESSAGE.KMAC_DELETION ->
                {
                    return KmacDeletion.EncodeObject();
                }
                case OFFLINE_KM_MESSAGE.CONF_KMAC_EXCHANGE ->
                {
                    return ConfKmacExchange.EncodeObject();
                }
                case OFFLINE_KM_MESSAGE.CONF_KMAC_UPDATE ->
                {
                    return ConfKmacUpdate.EncodeObject();
                }
                case OFFLINE_KM_MESSAGE.KMAC_NEGACK ->
                {
                    return KmacNegack.EncodeObject();
                }
                case OFFLINE_KM_MESSAGE.KMAC_UPDATE ->
                {
                    return KmacUpdate.EncodeObject();
                }
                default ->
                {
                    return returnErrorBuffer;
                }
            }
        }
        catch(NullPointerException e)
        {
            NullPointerException exception = new NullPointerException("The object you are trying to extract packets from has not been initialized");
            exception.setStackTrace(e.getStackTrace());
            super.IsExceptionPrintingAndWriteLog(exception);

            return returnErrorBuffer;
        }
    }

    /***
     * Creates a KMAC_NEGACK object using the input object and reason code.
     * @param obKmacDeletion request object
     * @param bReasonCode Information on why this message is generated
     */
    public void SetNegackResponseFromRequestObject(KmacDeletion obKmacDeletion, byte bReasonCode){
        InitInstanceFiledValues();
        SetKmacNegack( new KmacNegack(obKmacDeletion) );
        KmacNegack.SetReason(bReasonCode);
    }

    /***
     * Creates a KMAC_NEGACK object using the input object and reason code.
     * @param obKmacExchange request object
     * @param bReasonCode Information on why this message is generated
     */

    public void SetNegackResponseFromRequestObject(KmacExchange obKmacExchange, byte bReasonCode){
        InitInstanceFiledValues();
        SetKmacNegack( new KmacNegack(obKmacExchange) );
        KmacNegack.SetReason(bReasonCode);
    }

    /***
     * Creates a KMAC_NEGACK object using the input object and reason code.
     * @param obKmacUpdate request object
     * @param bReasonCode Information on why this message is generated
     */
    public void SetNegackResponseFromRequestObject(KmacUpdate obKmacUpdate, byte bReasonCode){
        InitInstanceFiledValues();
        SetKmacNegack( new KmacNegack(obKmacUpdate) );
        KmacNegack.SetReason(bReasonCode);
    }

    /***
     * Create a response object using a request object and assign the response object using a setter.
     * When using the setter, the msg_type variable is also set, so when getPacket() is used later,
     * a response message of the corresponding type is generated.
     * The subtype of the KMAC_DELETION object must also be set.
     * @param obKmacDeletion request Object
     * @param bSubType Response message purpose
     */
    public void SetResponseFromRequestObject(KmacDeletion obKmacDeletion, byte bSubType){
        InitInstanceFiledValues();
        ConfKmacDeletion resultObject = new ConfKmacDeletion(obKmacDeletion);
        resultObject.SetSubType(bSubType);
        SetConfKmacDeletion(resultObject);
    }

    /***
     * Create a response object using a request object and assign the response object using a setter.
     * When using the setter, the msg_type variable is also set, so when getPacket() is used later,
     * a response message of the corresponding type is generated.
     * @param obKmacExchange request Object
     *
     */
    public void SetResponseFromRequestObject(KmacExchange obKmacExchange){
        InitInstanceFiledValues();
        ConfKmacExchange resultObject = new ConfKmacExchange(obKmacExchange);
        SetConfKmacExchange(resultObject);
    }

    /***
     * Create a response object using a request object and assign the response object using a setter.
     * When using the setter, the msg_type variable is also set, so when getPacket() is used later,
     * a response message of the corresponding type is generated.
     * @param obKmacUpdate request Object
     * @param subtype Response message purpose
     */
    public void SetResponseFromRequestObject(KmacUpdate obKmacUpdate, byte subtype){
        InitInstanceFiledValues();
        ConfKmacUpdate resultObject = new ConfKmacUpdate(obKmacUpdate);
        SetConfKmacUpdate(resultObject);
    }

    private void InitInstanceFiledValues()
    {
        ConfKmacDeletion = null;
        ConfKmacExchange = null;
        ConfKmacUpdate = null;
        KmacDeletion = null;
        KmacExchange = null;
        KmacUpdate = null;
        KmacNegack = null;
    }

    public byte GetKmMessageType()
    {
        return KmMessageType;
    }

    public void SetKmMessageType(byte kmMessageType)
    {
        KmMessageType = kmMessageType;
    }

    public ConfKmacDeletion GetConfKmacDeletion()
    {
        return ConfKmacDeletion;
    }

    public void SetConfKmacDeletion(ConfKmacDeletion confKmacDeletion)
    {
        ConfKmacDeletion = confKmacDeletion;
        KmMessageType = OFFLINE_KM_MESSAGE.CONF_KMAC_DELETION;
    }

    public ConfKmacExchange GetConfKmacExchange()
    {
        return ConfKmacExchange;
    }

    public void SetConfKmacExchange(ConfKmacExchange confKmacExchange)
    {
        ConfKmacExchange = confKmacExchange;
        KmMessageType = OFFLINE_KM_MESSAGE.CONF_KMAC_EXCHANGE;
    }

    public ConfKmacUpdate GetConfKmacUpdate()
    {
        return ConfKmacUpdate;
    }

    public void SetConfKmacUpdate(ConfKmacUpdate confKmacUpdate)
    {
        ConfKmacUpdate = confKmacUpdate;
        KmMessageType = OFFLINE_KM_MESSAGE.CONF_KMAC_UPDATE;
    }

    public KmacDeletion GetKmacDeletion()
    {
        return KmacDeletion;
    }

    public void SetKmacDeletion(KmacDeletion kmacDeletion)
    {
        KmacDeletion = kmacDeletion;
        KmMessageType = OFFLINE_KM_MESSAGE.KMAC_DELETION;
    }

    public KmacExchange GetKmacExchange()
    {
        return KmacExchange;
    }

    public void SetKmacExchange(KmacExchange kmacExchange)
    {
        KmacExchange = kmacExchange;
        KmMessageType = OFFLINE_KM_MESSAGE.KMAC_EXCHANGE;
    }

    public KmacUpdate GetKmacUpdate()
    {
        return KmacUpdate;
    }

    public void SetKmacUpdate(KmacUpdate kmacUpdate)
    {
        KmacUpdate = kmacUpdate;
        KmMessageType = OFFLINE_KM_MESSAGE.KMAC_UPDATE;
    }

    public KmacNegack GetKmacNegack()
    {
        return KmacNegack;
    }

    public void SetKmacNegack(KmacNegack kmacNegack)
    {
        KmacNegack = kmacNegack;
        KmMessageType = OFFLINE_KM_MESSAGE.KMAC_NEGACK;
    }
}
