package org.twostack.bitcoin.transaction;

import org.twostack.bitcoin.script.Script;

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
