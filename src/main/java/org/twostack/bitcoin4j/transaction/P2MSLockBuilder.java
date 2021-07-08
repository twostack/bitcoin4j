package org.twostack.bitcoin4j.transaction;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class P2MSLockBuilder extends LockingScriptBuilder{

    List<PublicKey> publicKeyList = new ArrayList<>();
    int requiredSigs = 0;
    boolean sorting = false;


    public P2MSLockBuilder(List<PublicKey> publicKeys, int requiredSigs){

        super();
        this.sorting = true; //default to true for sorting when not specified
        this.requiredSigs = requiredSigs;
        this.publicKeyList = publicKeys;

    }

    public P2MSLockBuilder(List<PublicKey> publicKeys, int requiredSigs, boolean sortKeys){

        super();
        this.sorting = sortKeys;
        this.requiredSigs = requiredSigs;
        this.publicKeyList = new ArrayList(publicKeys);

    }

    public P2MSLockBuilder(Script script){
       parse(script);
    }

    private void parse(Script script){

        if (script.getChunks().size() > 0){

            List<ScriptChunk> chunks = script.getChunks();

            if (chunks.get(chunks.size() - 1).opcode != ScriptOpCodes.OP_CHECKMULTISIG){
                throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                        "Malformed multisig script. OP_CHECKMULTISIG is missing");
            }

            int keyCount = chunks.get(chunks.size() - 2).opcode - 80;

            publicKeyList = new ArrayList<>();

            for (int i = 0; i <keyCount; i++){
                publicKeyList.add(PublicKey.fromBytes(chunks.get(i+1).data));
            }

            requiredSigs = chunks.get(0).opcode - 80;
        }else{
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                    "Invalid Script or Malformed Script");
        }
    }

    @Override
    public Script getLockingScript() {

        if (requiredSigs == 0){
            return new ScriptBuilder().build();
        }

        if (requiredSigs > publicKeyList.size()){
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "You can't have more signatures than public keys");
        }

        if (sorting){
            publicKeyList.sort((a, b) -> a.getPubKeyHex().compareTo(b.getPubKeyHex()));
        }

        ScriptBuilder builder = new ScriptBuilder();

        int numRequiredSigsCode = ScriptOpCodes.getOpCode(Integer.toString(requiredSigs)); //e.g. OP_3 means 3 / y

        builder.op(numRequiredSigsCode);

        for (PublicKey pubKey : publicKeyList) {
            builder.data(pubKey.getPubKeyBytes());
        }
        int pubkeyCountOpCode = ScriptOpCodes.getOpCode(Integer.toString(publicKeyList.size())); //e.g. OP_5 means x / 5 multisig

        builder.op(pubkeyCountOpCode);
        builder.op(ScriptOpCodes.OP_CHECKMULTISIG);

        return builder.build();

    }

    public List<PublicKey> getPublicKeys() {
        return new ArrayList<>(publicKeyList);
    }

    public int getRequiredSigs() {
        return requiredSigs;
    }

    public boolean isSorting() {
        return sorting;
    }


}
