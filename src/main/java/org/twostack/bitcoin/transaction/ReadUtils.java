package org.twostack.bitcoin.transaction;

import org.twostack.bitcoin.Sha256Hash;
import org.twostack.bitcoin.Utils;
import org.twostack.bitcoin.VarInt;
import org.twostack.bitcoin.exception.ProtocolException;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class ReadUtils {

    public static final int MAX_SIZE = 0x02000000; // 32MB

    private byte[] payload;
    private int cursor;

    public ReadUtils(byte[] payload){
        this.payload = payload;
        cursor = 0;
    }

    protected long readUint32() throws ProtocolException {
        try {
            long u = Utils.readUint32(payload, cursor);
            cursor += 4;
            return u;
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    protected long readInt64() throws ProtocolException {
        try {
            long u = Utils.readInt64(payload, cursor);
            cursor += 8;
            return u;
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    protected BigInteger readUint64() throws ProtocolException {
        // Java does not have an unsigned 64 bit type. So scrape it off the wire then flip.
        return new BigInteger(Utils.reverseBytes(readBytes(8)));
    }

    protected VarInt readVarInt() throws ProtocolException {
        return readVarInt(0);
    }

    protected VarInt readVarInt(int offset) throws ProtocolException {
        try {
            VarInt varint = new VarInt(payload, cursor + offset);
            cursor += offset + varint.getOriginalSizeInBytes();
            return varint;
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    private void checkReadLength(int length) throws ProtocolException {
        if ((length > MAX_SIZE) || (cursor + length > payload.length)) {
            throw new ProtocolException("Claimed value length too large: " + length);
        }
    }

    protected byte[] readBytes(int length) throws ProtocolException {
        checkReadLength(length);
        try {
            byte[] b = new byte[length];
            System.arraycopy(payload, cursor, b, 0, length);
            cursor += length;
            return b;
        } catch (IndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    protected byte readByte() throws ProtocolException {
        checkReadLength(1);
        return payload[cursor++];
    }

    protected byte[] readByteArray() throws ProtocolException {
        final int length = readVarInt().intValue();
        return readBytes(length);
    }

    protected String readStr() throws ProtocolException {
        int length = readVarInt().intValue();
        return length == 0 ? "" : new String(readBytes(length), StandardCharsets.UTF_8); // optimization for empty strings
    }

    protected Sha256Hash readHash() throws ProtocolException {
        // We have to flip it around, as it's been read off the wire in little endian.
        // Not the most efficient way to do this but the clearest.
        return Sha256Hash.wrapReversed(readBytes(32));
    }

    protected boolean hasMoreBytes() {
        return cursor < payload.length;
    }

}
