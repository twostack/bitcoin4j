package org.twostack.bitcoin4j.script.templates;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.*;

import java.util.ArrayList;
import java.util.List;

/**
 * Template for OP_RETURN data output scripts.
 * Matches both OP_RETURN and OP_FALSE OP_RETURN patterns.
 */
public class OpReturnTemplate implements ScriptTemplate {

    @Override
    public String getName() {
        return "OP_RETURN";
    }

    @Override
    public boolean matches(Script script) {
        List<ScriptChunk> chunks = script.getChunks();
        if (chunks.isEmpty()) return false;

        // OP_RETURN <data...>
        if (chunks.get(0).equalsOpCode(ScriptOpCodes.OP_RETURN)) {
            return true;
        }

        // OP_FALSE OP_RETURN <data...>
        if (chunks.size() >= 2
                && chunks.get(0).equalsOpCode(ScriptOpCodes.OP_FALSE)
                && chunks.get(1).equalsOpCode(ScriptOpCodes.OP_RETURN)) {
            return true;
        }

        return false;
    }

    @Override
    public boolean canBeSatisfiedBy(List<PublicKey> keys, Script script) {
        // OP_RETURN outputs are unspendable
        return false;
    }

    @Override
    public ScriptInfo extractScriptInfo(Script script) {
        if (!matches(script)) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                    "Script is not an OP_RETURN script");
        }

        List<ScriptChunk> chunks = script.getChunks();
        List<byte[]> dataChunks = new ArrayList<>();

        // Determine where data starts (after OP_RETURN or OP_FALSE OP_RETURN)
        int dataStart;
        if (chunks.get(0).equalsOpCode(ScriptOpCodes.OP_RETURN)) {
            dataStart = 1;
        } else {
            dataStart = 2;
        }

        for (int i = dataStart; i < chunks.size(); i++) {
            ScriptChunk chunk = chunks.get(i);
            if (chunk.data != null) {
                dataChunks.add(chunk.data);
            } else if (chunk.opcode >= ScriptOpCodes.OP_1 && chunk.opcode <= ScriptOpCodes.OP_16) {
                //one-byte pushes of 1..16 are minimally encoded as OP_1..OP_16
                dataChunks.add(new byte[]{(byte) Script.decodeFromOpN(chunk.opcode)});
            }
        }

        return new OpReturnScriptInfo(dataChunks);
    }
}
