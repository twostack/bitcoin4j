package org.twostack.bitcoin4j.transaction;

import org.twostack.bitcoin4j.exception.SignatureDecodeException;
import org.twostack.bitcoin4j.script.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class P2MSUnlockBuilder extends UnlockingScriptBuilder{

    /*
    Default constructor won't init signatures.
    Signatures are injected as part of signing process
     */
    public P2MSUnlockBuilder(){
        super();
    }

    public P2MSUnlockBuilder(List<TransactionSignature> signatures){
       super();
       this.signatures = new ArrayList<>(signatures); //copy signature list
    }

    public P2MSUnlockBuilder(Script script){
       parse(script) ;
    }

    private void parse(Script script){

        if (script.getChunks().size() > 0){

            List<ScriptChunk> chunks = script.getChunks();

            try {

                for (int i = 1; i < chunks.size(); i++) {
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
        builder.op(ScriptOpCodes.OP_0); //push a value to stack first. this will be ignored by multisig bug, but is required(by the bug).

        for (TransactionSignature signature : getSignatures()) {
            try {
                builder.data(signature.toTxFormat()); //DER signature followed by the sighash byte
            } catch (IOException ex) {
                throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Failed to encode signature: " + ex.getMessage());
            }
        }

        return builder.build();
    }
}
