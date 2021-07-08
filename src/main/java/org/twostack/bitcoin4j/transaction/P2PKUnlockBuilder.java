package org.twostack.bitcoin4j.transaction;

import org.twostack.bitcoin4j.exception.SignatureDecodeException;
import org.twostack.bitcoin4j.script.*;

import java.util.List;

public class P2PKUnlockBuilder extends UnlockingScriptBuilder{

    public P2PKUnlockBuilder(TransactionSignature signature){
        addSignature(signature);
    }

    public P2PKUnlockBuilder(Script script){
        parse(script);
    }

    @Override
    public Script getUnlockingScript() {

        List<TransactionSignature> signatures = getSignatures();

        TransactionSignature signature = null;
        if (!signatures.isEmpty()) {
            signature = getSignatures().get(0);
        }

        if (signature == null){
            return new ScriptBuilder().build(); //return empty script; otherwise we will barf on early serialize (prior to signing)
        }

        try {
            return new ScriptBuilder().data(signature.toTxFormat()).build();
        }catch(Exception ex){
            System.out.println(ex.getMessage());
            ex.printStackTrace(); //FIXME: Handle more gracefully
            return new ScriptBuilder().build();
        }

    }

    private void parse(Script script) {

        if (script == null){
           throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Script value cannot be null.");
        }

        List<ScriptChunk> chunkList = script.getChunks();

        if (chunkList.size() != 1){
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Wrong number of data elements for P2PK ScriptSig");
        }

        byte[] sig = chunkList.get(0).data;

        try {
            signatures.add(TransactionSignature.fromTxFormat(sig));
        }catch (SignatureDecodeException ex){
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Script signature is invalid : " + ex.getMessage());
        }

    }
}
