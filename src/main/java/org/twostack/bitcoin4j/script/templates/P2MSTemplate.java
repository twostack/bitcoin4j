package org.twostack.bitcoin4j.script.templates;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.twostack.bitcoin4j.script.Script.decodeFromOpN;

/**
 * Template for Pay-to-Multisig scripts.
 * Pattern: [m] [keys...] [n] OP_CHECKMULTISIG
 */
public class P2MSTemplate implements ScriptTemplate {

    @Override
    public String getName() {
        return "P2MS";
    }

    @Override
    public boolean matches(Script script) {
        return ScriptPattern.isSentToMultisig(script);
    }

    @Override
    public boolean canBeSatisfiedBy(List<PublicKey> keys, Script script) {
        if (!matches(script) || keys == null || keys.isEmpty()) {
            return false;
        }

        List<ScriptChunk> chunks = script.getChunks();
        int threshold = decodeFromOpN(chunks.get(0).opcode);

        // Check how many of the provided keys match keys in the script
        int matchCount = 0;
        for (int i = 1; i < chunks.size() - 2; i++) {
            byte[] scriptKeyBytes = chunks.get(i).data;
            if (scriptKeyBytes != null) {
                for (PublicKey key : keys) {
                    if (Arrays.equals(key.getPubKeyBytes(), scriptKeyBytes)) {
                        matchCount++;
                        break;
                    }
                }
            }
        }
        return matchCount >= threshold;
    }

    @Override
    public ScriptInfo extractScriptInfo(Script script) {
        if (!matches(script)) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                    "Script is not a P2MS script");
        }

        List<ScriptChunk> chunks = script.getChunks();
        int threshold = decodeFromOpN(chunks.get(0).opcode);
        int totalKeys = decodeFromOpN(chunks.get(chunks.size() - 2).opcode);

        List<byte[]> publicKeys = new ArrayList<>();
        for (int i = 1; i <= totalKeys; i++) {
            publicKeys.add(chunks.get(i).data);
        }

        return new P2MSScriptInfo(threshold, totalKeys, publicKeys);
    }
}
