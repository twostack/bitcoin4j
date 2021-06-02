package org.twostack.bitcoin.transaction;

import org.twostack.bitcoin.script.Script;
import org.twostack.bitcoin.script.ScriptBuilder;

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
