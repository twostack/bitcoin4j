package org.twostack.bitcoin4j.transaction;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

public class WriteUtils {

    private ByteArrayOutputStream bos = new ByteArrayOutputStream();


    public void writeBytes(byte[] bytes, int length) {
        bos.write(bytes, 0, length);
    }

    public void writeUint8LE(int val) throws IOException{
        bos.write((int) (0xFF & val));
    }

    /** Write 2 bytes to the output stream as unsigned 16-bit integer in little endian format. */
    public void writeUint16LE(int val) throws IOException {
        bos.write((int) (0xFF & val));
        bos.write((int) (0xFF & (val >> 8)));
    }

    /** Write 2 bytes to the output stream as unsigned 16-bit integer in big endian format. */
    public void writeUint16BE(int val) throws IOException {
        bos.write((int) (0xFF & (val >> 8)));
        bos.write((int) (0xFF & val));
    }

    /** Write 4 bytes to the output stream as unsigned 32-bit integer in little endian format. */
    public void writeUint32LE(long val) throws IOException {
        bos.write((int) (0xFF & val));
        bos.write((int) (0xFF & (val >> 8)));
        bos.write((int) (0xFF & (val >> 16)));
        bos.write((int) (0xFF & (val >> 24)));
    }

    /** Write 4 bytes to the output stream as unsigned 32-bit integer in big endian format. */
    public void writeUint32BE(long val) throws IOException {
        bos.write((int) (0xFF & (val >> 24)));
        bos.write((int) (0xFF & (val >> 16)));
        bos.write((int) (0xFF & (val >> 8)));
        bos.write((int) (0xFF & val));
    }

    /** Write 8 bytes to the output stream as signed 64-bit integer in little endian format. */
    public void writeInt64LE(long val) throws IOException {
        bos.write((int) (0xFF & val));
        bos.write((int) (0xFF & (val >> 8)));
        bos.write((int) (0xFF & (val >> 16)));
        bos.write((int) (0xFF & (val >> 24)));
        bos.write((int) (0xFF & (val >> 32)));
        bos.write((int) (0xFF & (val >> 40)));
        bos.write((int) (0xFF & (val >> 48)));
        bos.write((int) (0xFF & (val >> 56)));
    }

    /** Write 8 bytes to the output stream as unsigned 64-bit integer in little endian format. */
    public void writeUint64LE(BigInteger val) throws IOException {
        byte[] bytes = val.toByteArray();
        if (bytes.length > 8) {
            throw new RuntimeException("Input too large to encode into a uint64");
        }
        bytes = reverseBytes(bytes);
        bos.write(bytes);
        if (bytes.length < 8) {
            for (int i = 0; i < 8 - bytes.length; i++)
                bos.write(0);
        }
    }


    /**
     * Returns a copy of the given byte array in reverse order.
     */
    public byte[] reverseBytes(byte[] bytes) {
        // We could use the XOR trick here but it's easier to understand if we don't. If we find this is really a
        // performance issue the matter can be revisited.
        byte[] buf = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++)
            buf[i] = bytes[bytes.length - 1 - i];
        return buf;
    }

    public byte[] getBytes(){
        return bos.toByteArray();
    }
}
