package org.twostack.bitcoin4j.transaction;

import org.twostack.bitcoin4j.script.Script;

import java.util.ArrayList;
import java.util.List;

public class DefaultUnlockBuilder extends UnlockingScriptBuilder {

    List<TransactionSignature> signatures = new ArrayList<>();

    DefaultUnlockBuilder(){
        super();
    }

    DefaultUnlockBuilder(Script script){
        super(script);
    }

    @Override
    public Script getScriptSig() {
        return script;
    }

}
