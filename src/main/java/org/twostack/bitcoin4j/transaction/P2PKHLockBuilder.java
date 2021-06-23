
/*
 * Copyright 2021 Stephan M. February
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.twostack.bitcoin4j.transaction;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.Address;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.bitcoin4j.script.*;

import java.util.List;

import static org.twostack.bitcoin4j.script.ScriptOpCodes.*;

public class P2PKHLockBuilder extends LockingScriptBuilder{

    Address address;
    byte[] pubkeyHash;

    static P2PKHLockBuilder fromPublicKey(PublicKey key, NetworkAddressType networkType){
        Address address = Address.fromKey(networkType, key);
        return new P2PKHLockBuilder(address);
    }

    public P2PKHLockBuilder(Address address){
        this.address = address;

        if (address != null) {
            this.pubkeyHash = address.getHash(); //hash160(pubkey) aka pubkeyHash
        }
    }

    public P2PKHLockBuilder(Script script){
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
    public Script getLockingScript() {

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
