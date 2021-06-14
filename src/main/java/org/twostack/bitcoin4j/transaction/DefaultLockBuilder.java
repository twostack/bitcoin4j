package org.twostack.bitcoin4j.transaction;

import org.twostack.bitcoin4j.script.Script;

public class DefaultLockBuilder extends LockingScriptBuilder{

    public DefaultLockBuilder(Script script){
       super(script);
    }

    public DefaultLockBuilder(){
       super();
    }

    @Override
    public Script getScriptPubkey() {
        return script;
    }
}
