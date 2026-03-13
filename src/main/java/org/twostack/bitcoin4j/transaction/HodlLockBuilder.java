package org.twostack.bitcoin4j.transaction;

import org.twostack.bitcoin4j.script.*;

import java.math.BigInteger;
import java.util.List;

import static org.twostack.bitcoin4j.script.ScriptOpCodes.*;

/**
 * Locking script builder for HODLocker timelock scripts.
 * Pattern: {@code <lockHeight> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG}
 */
public class HodlLockBuilder extends LockingScriptBuilder {

    private byte[] pubKeyHash;
    private BigInteger lockHeight;

    public HodlLockBuilder(byte[] pubKeyHash, BigInteger lockHeight) {
        this.pubKeyHash = pubKeyHash;
        this.lockHeight = lockHeight;
    }

    /**
     * Factory to create a HodlLockBuilder from an existing script.
     */
    public static HodlLockBuilder fromScript(Script script) {
        if (script == null) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                    "Invalid Script or Malformed Script.");
        }

        List<ScriptChunk> chunks = script.getChunks();
        if (chunks.size() != 8) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                    "Wrong number of data elements for HODLocker script");
        }

        if (!(chunks.get(1).equalsOpCode(OP_CHECKLOCKTIMEVERIFY)
                && chunks.get(2).equalsOpCode(OP_DROP)
                && chunks.get(3).equalsOpCode(OP_DUP)
                && chunks.get(4).equalsOpCode(OP_HASH160)
                && chunks.get(6).equalsOpCode(OP_EQUALVERIFY)
                && chunks.get(7).equalsOpCode(OP_CHECKSIG))) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                    "Malformed HODLocker script. Mismatched OP_CODES.");
        }

        byte[] lockHeightBytes = chunks.get(0).data;
        if (lockHeightBytes == null) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                    "Missing lock height in HODLocker script");
        }

        byte[] pubKeyHash = chunks.get(5).data;
        if (pubKeyHash == null || pubKeyHash.length != 20) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                    "Missing or invalid pubKeyHash in HODLocker script");
        }

        // Decode lock height from little-endian script number
        BigInteger lockHeight = new BigInteger(1, reverseBytes(lockHeightBytes));

        return new HodlLockBuilder(pubKeyHash, lockHeight);
    }

    @Override
    public Script getLockingScript() {
        if (pubKeyHash == null) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                    "Missing pubKeyHash. Can't construct the script.");
        }
        if (lockHeight == null) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                    "Missing lockHeight. Can't construct the script.");
        }

        ScriptBuilder builder = new ScriptBuilder();
        builder.data(encodeLockHeight(lockHeight));
        builder.op(OP_CHECKLOCKTIMEVERIFY);
        builder.op(OP_DROP);
        builder.op(OP_DUP);
        builder.op(OP_HASH160);
        builder.data(pubKeyHash);
        builder.op(OP_EQUALVERIFY);
        builder.op(OP_CHECKSIG);

        return builder.build();
    }

    public byte[] getPubKeyHash() {
        return pubKeyHash;
    }

    public BigInteger getLockHeight() {
        return lockHeight;
    }

    /**
     * Encodes a lock height as a minimal little-endian script number.
     */
    private static byte[] encodeLockHeight(BigInteger value) {
        if (value.equals(BigInteger.ZERO)) {
            return new byte[0];
        }

        byte[] result = value.toByteArray();
        // BigInteger uses big-endian, we need little-endian
        byte[] reversed = reverseBytes(result);

        // Remove leading zero byte if BigInteger added one for sign
        if (reversed.length > 1 && reversed[reversed.length - 1] == 0) {
            byte[] trimmed = new byte[reversed.length - 1];
            System.arraycopy(reversed, 0, trimmed, 0, trimmed.length);
            return trimmed;
        }

        return reversed;
    }

    private static byte[] reverseBytes(byte[] bytes) {
        byte[] reversed = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            reversed[i] = bytes[bytes.length - 1 - i];
        }
        return reversed;
    }
}
