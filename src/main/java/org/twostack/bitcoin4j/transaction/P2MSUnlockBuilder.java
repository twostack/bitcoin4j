package org.twostack.bitcoin4j.transaction;

import org.twostack.bitcoin4j.exception.SignatureDecodeException;
import org.twostack.bitcoin4j.script.*;

import java.util.List;

public class P2MSUnlockBuilder extends UnlockingScriptBuilder{

    public P2MSUnlockBuilder(Script script){
       parse(script) ;
    }

    private void parse(Script script){

        if (script.getChunks().size() > 0){

            List<ScriptChunk> chunks = script.getChunks();

            try {

                for (int i = 0; i < chunks.size(); i++) {
                    signatures.add(TransactionSignature.fromTxFormat(chunks.get(i).data));
                }

            }catch(SignatureDecodeException ex){
                throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                        "Script parsing failed. Invalid signatures detected.");
            }

        }else{
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                    "Invalid script or malformed script");
        }

    }

    @Override
    public Script getUnlockingScript() {

        ScriptBuilder builder = new ScriptBuilder();
        builder.op(ScriptOpCodes.OP_0);

        for (TransactionSignature signature : signatures) {
            builder.data(signature.getSignatureBytes());
        }

        return builder.build();
    }
}
