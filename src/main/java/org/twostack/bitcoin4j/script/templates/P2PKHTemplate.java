package org.twostack.bitcoin4j.script.templates;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.*;

import java.util.Arrays;
import java.util.List;

/**
 * Template for Pay-to-Public-Key-Hash scripts.
 * Pattern: {@code OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG}
 */
public class P2PKHTemplate implements ScriptTemplate {

    @Override
    public String getName() {
        return "P2PKH";
    }

    @Override
    public boolean matches(Script script) {
        return ScriptPattern.isP2PKH(script);
    }

    @Override
    public boolean canBeSatisfiedBy(List<PublicKey> keys, Script script) {
        if (!matches(script) || keys == null || keys.isEmpty()) {
            return false;
        }
        byte[] scriptPubKeyHash = ScriptPattern.extractHashFromP2PKH(script);
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
                    "Script is not a P2PKH script");
        }
        return new P2PKHScriptInfo(ScriptPattern.extractHashFromP2PKH(script));
    }
}
