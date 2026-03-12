package org.twostack.bitcoin4j.transaction;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptBuilder;
import org.twostack.bitcoin4j.script.ScriptException;
import org.twostack.bitcoin4j.script.ScriptError;

import java.io.IOException;

/**
 * Unlocking script builder for HODLocker timelock scripts.
 * Pattern: <sig> <pubKey> <preImage>
 */
public class HodlUnlockBuilder extends UnlockingScriptBuilder {

    private final PublicKey pubKey;
    private final byte[] preImage;

    public HodlUnlockBuilder(TransactionSignature sig, PublicKey pubKey, byte[] preImage) {
        this.pubKey = pubKey;
        this.preImage = preImage;
        if (sig != null) {
            addSignature(sig);
        }
    }

    @Override
    public Script getUnlockingScript() {
        ScriptBuilder builder = new ScriptBuilder();

        if (!signatures.isEmpty()) {
            try {
                builder.data(signatures.get(0).toTxFormat());
            } catch (IOException e) {
                throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                        "Failed to serialize signature: " + e.getMessage());
            }
        }

        if (pubKey != null) {
            builder.data(pubKey.getPubKeyBytes());
        }

        if (preImage != null) {
            builder.data(preImage);
        }

        return builder.build();
    }
}
