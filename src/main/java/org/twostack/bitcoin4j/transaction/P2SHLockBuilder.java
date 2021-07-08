package org.twostack.bitcoin4j.transaction;

import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.*;

import java.nio.ByteBuffer;

public class P2SHLockBuilder extends LockingScriptBuilder{

    ByteBuffer scriptHash;

    public P2SHLockBuilder(ByteBuffer scriptHash){
        this.scriptHash = scriptHash;
    }

    public P2SHLockBuilder(Script script){

        if (script != null){
            byte[]  byteBuffer = Utils.sha256hash160(script.getProgram());

            this.scriptHash = ByteBuffer.wrap(byteBuffer);
        }else{
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Invalid script or malformed script");
        }
    }

    @Override
    public Script getLockingScript() {

        if (scriptHash == null){
            return new ScriptBuilder().build();
        }

        ScriptBuilder builder = new ScriptBuilder();
        builder.op(ScriptOpCodes.OP_HASH160);
        builder.data(scriptHash.array());
        builder.op(ScriptOpCodes.OP_EQUAL);

        return builder.build();
    }
}
