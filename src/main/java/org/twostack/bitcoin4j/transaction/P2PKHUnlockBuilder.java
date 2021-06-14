
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
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.exception.SignatureDecodeException;
import org.twostack.bitcoin4j.script.*;

import java.util.List;

public class P2PKHUnlockBuilder extends UnlockingScriptBuilder {

    PublicKey signerPubkey;

    public P2PKHUnlockBuilder(Script script) throws SignatureDecodeException {
        parse(script);
    }

    public P2PKHUnlockBuilder(PublicKey publicKey) {
        this.signerPubkey = publicKey;
    }

    private void parse(Script script) throws SignatureDecodeException {

        if (script != null) {

            List<ScriptChunk> chunkList = script.getChunks();

            if (chunkList.size() != 2){
                throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Wrong number of data elements for P2PKH ScriptSig");
            }

            byte[] sig = chunkList.get(0).data;
            byte[] pubKey = chunkList.get(1).data;

            signerPubkey = PublicKey.fromHex(Utils.HEX.encode(pubKey));
            signatures.add(TransactionSignature.fromTxFormat(Utils.HEX.encode(sig)));

        }else{
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Invalid Script or Malformed Script.");
        }
    }

    @Override
    public Script getScriptSig() {

        List<TransactionSignature> signatures = getSignatures();

        TransactionSignature signature = null;
        if (!signatures.isEmpty()) {
            signature = getSignatures().get(0);
        }

        if (signature == null || signerPubkey == null){
            return new ScriptBuilder().build(); //return empty script; otherwise we will barf on early serialize (prior to signing)
        }

        try {

            return new ScriptBuilder().data(signature.toTxFormat()).data(signerPubkey.getPubKeyBytes()).build();
        }catch(Exception ex){
            System.out.println(ex.getMessage());
            ex.printStackTrace(); //FIXME: Handle more gracefully
            return new ScriptBuilder().build();
        }
    }
}
