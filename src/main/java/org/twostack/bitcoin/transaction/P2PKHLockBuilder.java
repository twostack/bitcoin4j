package org.twostack.bitcoin.transaction;

import org.twostack.bitcoin.PublicKey;
import org.twostack.bitcoin.Address;
import org.twostack.bitcoin.params.NetworkAddressType;
import org.twostack.bitcoin.script.*;

import java.util.List;

import static org.twostack.bitcoin.script.ScriptOpCodes.*;

public class P2PKHLockBuilder extends LockingScriptBuilder{

    Address address;
    byte[] pubkeyHash;

    static P2PKHLockBuilder fromPublicKey(PublicKey key, NetworkAddressType networkType){
        Address address = Address.fromKey(networkType, key);
        return new P2PKHLockBuilder(address);
    }

    P2PKHLockBuilder(Address address){
        this.address = address;

        if (address != null) {
            this.pubkeyHash = address.getHash(); //hash160(pubkey) aka pubkeyHash
        }
    }

    P2PKHLockBuilder(Script script){
        parse(script);
    }

    private void parse(Script script){

        if (script != null) {

            List<ScriptChunk> chunkList = script.getChunks();

            if (chunkList.size() != 5){
                throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,"Wrong number of data elements for P2PKH ScriptPubkey");
            }

            if (chunkList.get(2).size() != 20 ){
                throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Signature and Public Key values are malformed");
            }

            if(!(   chunkList.get(0).opcode == ScriptOpCodes.OP_DUP &&
                    chunkList.get(1).opcode == ScriptOpCodes.OP_HASH160 &&
                    chunkList.get(3).opcode == ScriptOpCodes.OP_EQUALVERIFY &&
                    chunkList.get(4).opcode == ScriptOpCodes.OP_CHECKSIG )){
                throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Malformed P2PKH ScriptPubkey script. Mismatched OP_CODES.");
            }

            this.pubkeyHash = chunkList.get(2).data;

        }else{
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Invalid Script or Malformed Script.");
        }
    }

    @Override
    public Script getScriptPubkey() {

        if (this.pubkeyHash == null) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Missing pubkeyHash. Can't construct the script.");
        }

        ScriptBuilder builder = new ScriptBuilder();
        builder.op(OP_DUP);
        builder.op(OP_HASH160);
        builder.data(this.pubkeyHash);
        builder.op(OP_EQUALVERIFY);
        builder.op(OP_CHECKSIG);

        return builder.build();

    }
}
