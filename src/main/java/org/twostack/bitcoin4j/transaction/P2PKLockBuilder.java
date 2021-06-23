package org.twostack.bitcoin4j.transaction;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.*;

import java.util.List;

import static org.twostack.bitcoin4j.script.ScriptOpCodes.OP_CHECKSIG;

public class P2PKLockBuilder extends LockingScriptBuilder {

    private PublicKey signerPubkey;

    public P2PKLockBuilder(Script script) {
        parse(script);
    }

    private void parse(Script script) {

        if (script == null) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Invalid Script or Malformed Script.");
        }

        if (script != null) {

            List<ScriptChunk> chunkList = script.getChunks();

            if (chunkList.size() != 2) {
                throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Wrong number of data elements for P2PK Locking Script");
            }

            if (chunkList.get(1).opcode != ScriptOpCodes.OP_CHECKSIG) {
                throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Malformed P2PK Locking Script. Mismatched OP_CODES.");
            }

            signerPubkey = PublicKey.fromBytes(chunkList.get(0).data);
        }
    }

    @Override
    public Script getLockingScript() {

        if (this.signerPubkey == null) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Missing Public Key. Can't construct the script.");
        }

        ScriptBuilder builder = new ScriptBuilder();
        builder.data(this.signerPubkey.getPubKeyBytes());
        builder.op(OP_CHECKSIG);

        return builder.build();

    }
}
