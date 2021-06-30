
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

import org.twostack.bitcoin4j.ECKey;
import org.twostack.bitcoin4j.PrivateKey;
import org.twostack.bitcoin4j.exception.SigHashException;
import org.twostack.bitcoin4j.exception.SignatureDecodeException;
import org.twostack.bitcoin4j.exception.TransactionException;
import org.twostack.bitcoin4j.script.Script;

import java.io.IOException;

public class TransactionSigner {

    public Transaction sign(
            Transaction unsignedTxn,
            TransactionOutput utxo,
            int inputIndex,
            PrivateKey signingKey,
            int sigHashType) throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        //FIXME: This is a test work-around for why I can't sign an unsigned raw txn
        //FIXME: This assumes we're signing P2PKH


        //FIXME: This should account for ANYONECANPAY mask that limits outputs to sign over
        ///      NOTE: Stripping Subscript should be done inside SIGHASH class
        Script subscript = utxo.getScript(); //scriptSig FIXME: WTF !? Sighash should fail on this
        SigHash sigHash = new SigHash();

        //NOTE: Return hash in LittleEndian (already double-sha256 applied)
        byte[] hash = sigHash.createHash(unsignedTxn, sigHashType, inputIndex, subscript, utxo.getAmount());

        //FIXME: Revisit this issue surrounding the need to sign a reversed copy of the hash.
        ///      Right now I've factored this out of signature.dart because 'coupling' & 'separation of concerns'.
        //       var reversedHash = Utils.HEX.encode(HEX.decode(hash).reversed.toList());

        // generate a signature for the input
        // TransactionSignature is just a thin wrapper over our signature to assert
        // type safety during serializing of our TransactionOutput


        //FIXME: This kind of required round-tripping into the base class of TransactionSignature smells funny
        //       We should have a cleaner constructor for TransactionSignature
        byte[] signedBytes =  signingKey.sign(hash);
        ECKey.ECDSASignature ecSig = ECKey.ECDSASignature.decodeFromDER(signedBytes);
        TransactionSignature sig = new TransactionSignature(ecSig.r, ecSig.s, sigHashType);

        TransactionInput input = unsignedTxn.getInputs().get(inputIndex);
        UnlockingScriptBuilder scriptBuilder = input.getUnlockingScriptBuilder();

        if (scriptBuilder != null) {
            scriptBuilder.addSignature(sig);
        }else{
            throw new TransactionException("Trying to sign a Transaction Input that is missing a SignedUnlockBuilder");
        }

        return unsignedTxn; //signature has been added
    }


    /** sf:> This seems like more Core buggery to me. What sort of TX remains valid without proper SighashType ???
     *
     * This is required for signatures which use a sigHashType which cannot be represented using SigHash and anyoneCanPay
     * See transaction c99c49da4c38af669dea436d3e73780dfdb6c1ecf9958baa52960e8baee30e73, which has sigHashType 0
     */
//    public Sha256Hash hashForSignature(Transaction txn, int inputIndex, byte[] connectedScript, byte sigHashType) {
//
//    }

}
