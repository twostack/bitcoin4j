package org.twostack.bitcoin4j.script.templates;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.*;

import java.util.List;

/**
 * Template for Pay-to-Script-Hash scripts.
 * Pattern: {@code OP_HASH160 <scriptHash> OP_EQUAL}
 */
public class P2SHTemplate implements ScriptTemplate {

    @Override
    public String getName() {
        return "P2SH";
    }

    @Override
    public boolean matches(Script script) {
        return ScriptPattern.isP2SH(script);
    }

    @Override
    public boolean canBeSatisfiedBy(List<PublicKey> keys, Script script) {
        // P2SH spendability depends on the redeem script, not just the keys
        return false;
    }

    @Override
    public ScriptInfo extractScriptInfo(Script script) {
        if (!matches(script)) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                    "Script is not a P2SH script");
        }
        return new P2SHScriptInfo(ScriptPattern.extractHashFromP2SH(script));
    }
}
