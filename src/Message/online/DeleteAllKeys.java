package Message.online;

import Message.CodecUtil;
import Message.constant.Common.*;

/** Message for deleting all key entries stored in the receiving KMAC entity.
 This message consists only of the message header. */
public class DeleteAllKeys extends CodecUtil
{
    /** This message consists only of the message header */
    public DeleteAllKeys() {}

    public int GetSize()
    {
        return COMMON_SIZE.EMPTY;
    }

    public void EncodeObject()
    {
        /* This message consists only of the message header */
    }
}

