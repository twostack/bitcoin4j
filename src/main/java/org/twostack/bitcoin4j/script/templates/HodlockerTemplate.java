package org.twostack.bitcoin4j.script.templates;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.*;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import static org.twostack.bitcoin4j.script.ScriptOpCodes.*;

/**
 * Template for HODLocker timelock scripts.
 * Pattern: {@code <lockHeight> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG}
 */
public class HodlockerTemplate implements ScriptTemplate {

    @Override
    public String getName() {
        return "HODLocker";
    }

    @Override
    public boolean matches(Script script) {
        List<ScriptChunk> chunks = script.getChunks();
        if (chunks.size() != 8) return false;

        // chunk 0: lockHeight (data push)
        if (chunks.get(0).data == null) return false;

        // chunk 1: OP_CHECKLOCKTIMEVERIFY
        if (!chunks.get(1).equalsOpCode(OP_CHECKLOCKTIMEVERIFY)) return false;

        // chunk 2: OP_DROP
        if (!chunks.get(2).equalsOpCode(OP_DROP)) return false;

        // chunk 3: OP_DUP
        if (!chunks.get(3).equalsOpCode(OP_DUP)) return false;

        // chunk 4: OP_HASH160
        if (!chunks.get(4).equalsOpCode(OP_HASH160)) return false;

        // chunk 5: pubKeyHash (20 bytes)
        if (chunks.get(5).data == null || chunks.get(5).data.length != 20) return false;

        // chunk 6: OP_EQUALVERIFY
        if (!chunks.get(6).equalsOpCode(OP_EQUALVERIFY)) return false;

        // chunk 7: OP_CHECKSIG
        if (!chunks.get(7).equalsOpCode(OP_CHECKSIG)) return false;

        return true;
    }

    @Override
    public boolean canBeSatisfiedBy(List<PublicKey> keys, Script script) {
        if (!matches(script) || keys == null || keys.isEmpty()) {
            return false;
        }
        byte[] scriptPubKeyHash = script.getChunks().get(5).data;
        for (PublicKey key : keys) {
            if (Arrays.equals(key.getPubKeyHash(), scriptPubKeyHash)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public ScriptInfo extractScriptInfo(Script script) {
        if (!matches(script)) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                    "Script is not a HODLocker script");
        }

        List<ScriptChunk> chunks = script.getChunks();
        byte[] lockHeightBytes = chunks.get(0).data;
        byte[] pubKeyHash = chunks.get(5).data;

        // Decode lock height from little-endian script number
        BigInteger lockHeight = new BigInteger(1, reverseBytes(lockHeightBytes));

        return new HodlockerScriptInfo(pubKeyHash, lockHeight);
    }

    private static byte[] reverseBytes(byte[] bytes) {
        byte[] reversed = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            reversed[i] = bytes[bytes.length - 1 - i];
        }
        return reversed;
    }
}
