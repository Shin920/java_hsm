package communication.packet;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;

public class PacketUtil
{
    public final byte ERROR_BYTE = (byte)0XCD; /* CD(Collision Detection) */

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
     * @param nByteSize Making Buffer Length
     * @return Error bufferArray to fill(0xff)
     */
    public byte[] MakeErrorPacket(int nByteSize)
    {
        byte[] errorBuffer = new byte[nByteSize];
        Arrays.fill(errorBuffer, ERROR_BYTE);
        return errorBuffer;
    }
}
