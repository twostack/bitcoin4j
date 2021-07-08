package org.twostack.bitcoin4j.transaction;

import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptError;
import org.twostack.bitcoin4j.script.ScriptException;

public class P2SHUnlockBuilder extends UnlockingScriptBuilder{

    Script script;

    public P2SHUnlockBuilder(Script script){
        if (script != null) {
            this.script = script;
        }else{
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Invalid or malformed script");
        }
    }

    @Override
    public Script getUnlockingScript() {
        return script;

    }
}
