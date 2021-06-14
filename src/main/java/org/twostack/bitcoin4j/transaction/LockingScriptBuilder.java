package org.twostack.bitcoin4j.transaction;

import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptBuilder;

public abstract class LockingScriptBuilder {

    protected Script script;

    public abstract Script getScriptPubkey();

    public LockingScriptBuilder(){
        this.script = new ScriptBuilder().build();
    }

    public LockingScriptBuilder(Script script){
        this.script = script;
    }
}
