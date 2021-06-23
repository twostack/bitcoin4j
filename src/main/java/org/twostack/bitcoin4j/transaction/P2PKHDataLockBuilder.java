package org.twostack.bitcoin4j.transaction;

import org.twostack.bitcoin4j.Address;
import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.bitcoin4j.script.*;

import java.nio.ByteBuffer;
import java.util.List;

import static org.twostack.bitcoin4j.script.ScriptOpCodes.*;
import static org.twostack.bitcoin4j.script.ScriptOpCodes.OP_CHECKSIG;

/**
 * A combination of P2PKH and an "OP_PUSHDATA [data] OP_DROP" pre-prended to the
 * Locking Script. This results in a spendable output that has data attached.
 * The implication here is that spending the output signs over the data.
 *
 * Combined locking + unlocking script has this shape:
 *
 * 'OP_PUSHDATA1 32 0x2606168dabed7b4d11fdd242317adb480ee8c4fa7330db1a8b4f1c7749072aea OP_DROP OP_DUP OP_HASH160 20 0x581e5e328b0d34d724c09f123c050b341d11d96c OP_EQUALVERIFY OP_CHECKSIG'
 *
 */
public class P2PKHDataLockBuilder extends LockingScriptBuilder{

    Address address;
    byte[] pubkeyHash;

    ByteBuffer dataBuffer;

    static P2PKHDataLockBuilder fromPublicKey(PublicKey key, ByteBuffer data, NetworkAddressType networkType){
        Address address = Address.fromKey(networkType, key);
        return new P2PKHDataLockBuilder(address, data);
    }

    public P2PKHDataLockBuilder(Address address, ByteBuffer data){
        this.address = address;

        if (address != null) {
            this.pubkeyHash = address.getHash(); //hash160(pubkey) aka pubkeyHash
        }
    }

    public P2PKHDataLockBuilder(Script script){
        parse(script);
    }

    private void parse(Script script){

        if (script != null) {

            List<ScriptChunk> chunkList = script.getChunks();

            if (chunkList.size() != 8){
                throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,"Wrong number of data elements for locking script");
            }

            if (chunkList.get(5).size() != 20 ){
                throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Signature and Public Key values are malformed");
            }

            if(!(   chunkList.get(3).opcode == ScriptOpCodes.OP_DUP &&
                    chunkList.get(4).opcode == ScriptOpCodes.OP_HASH160 &&
                    chunkList.get(7).opcode == ScriptOpCodes.OP_EQUALVERIFY &&
                    chunkList.get(8).opcode == ScriptOpCodes.OP_CHECKSIG )){
                throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Malformed script. Mismatched OP_CODES.");
            }

            this.dataBuffer = ByteBuffer.wrap(chunkList.get(1).data);

            this.pubkeyHash = chunkList.get(5).data;

        }else{
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Invalid Script or Malformed Script.");
        }
    }

    @Override
    public Script getLockingScript() {

        if (this.pubkeyHash == null) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Missing pubkeyHash. Can't construct the script.");
        }

        ScriptBuilder builder = new ScriptBuilder();
        builder.data(dataBuffer.array());
        builder.op(OP_DROP);
        builder.op(OP_DUP);
        builder.op(OP_HASH160);
        builder.data(this.pubkeyHash);
        builder.op(OP_EQUALVERIFY);
        builder.op(OP_CHECKSIG);

        return builder.build();

    }
}
