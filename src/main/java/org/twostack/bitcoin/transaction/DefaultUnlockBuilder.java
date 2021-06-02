package org.twostack.bitcoin.transaction;

import org.twostack.bitcoin.script.Script;

import java.util.ArrayList;
import java.util.Collections;
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
