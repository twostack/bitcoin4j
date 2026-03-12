package org.twostack.bitcoin4j.script.templates;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.*;

import java.util.Arrays;
import java.util.List;

/**
 * Template for Pay-to-Public-Key scripts.
 * Pattern: <pubKey> OP_CHECKSIG
 */
public class P2PKTemplate implements ScriptTemplate {

    @Override
    public String getName() {
        return "P2PK";
    }

    @Override
    public boolean matches(Script script) {
        return ScriptPattern.isP2PK(script);
    }

    @Override
    public boolean canBeSatisfiedBy(List<PublicKey> keys, Script script) {
        if (!matches(script) || keys == null || keys.isEmpty()) {
            return false;
        }
        byte[] scriptPubKey = ScriptPattern.extractKeyFromP2PK(script);
        for (PublicKey key : keys) {
            if (Arrays.equals(key.getPubKeyBytes(), scriptPubKey)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public ScriptInfo extractScriptInfo(Script script) {
        if (!matches(script)) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                    "Script is not a P2PK script");
        }
        return new P2PKScriptInfo(ScriptPattern.extractKeyFromP2PK(script));
    }
}
