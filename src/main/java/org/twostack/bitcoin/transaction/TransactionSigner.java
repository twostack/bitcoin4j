package org.twostack.bitcoin.transaction;

import org.twostack.bitcoin.PrivateKey;
import org.twostack.bitcoin.Utils;
import org.twostack.bitcoin.exception.SigHashException;
import org.twostack.bitcoin.exception.TransactionException;
import org.twostack.bitcoin.script.Script;

import java.io.IOException;

public class TransactionSigner {

    public Transaction sign(
            Transaction unsignedTxn,
            TransactionOutput utxo,
            int inputIndex,
            PrivateKey signingKey,
            int sigHashFlags) throws TransactionException, IOException, SigHashException {

        //FIXME: This is a test work-around for why I can't sign an unsigned raw txn
        //FIXME: This assumes we're signing P2PKH

        TransactionInput input = unsignedTxn.getInputs().get(inputIndex);

        //FIXME: This should account for ANYONECANPAY mask that limits outputs to sign over
        ///      NOTE: Stripping Subscript should be done inside SIGHASH class
        Script subscript = utxo.getScript(); //scriptSig FIXME: WTF !? Sighash should fail on this
        SigHash sigHash = new SigHash();

        //NOTE: Return hash in LittleEndian
        byte[] hash = sigHash.createHash(unsignedTxn, sigHashFlags, inputIndex, subscript, utxo.getAmount());

        //FIXME: Revisit this issue surrounding the need to sign a reversed copy of the hash.
        ///      Right now I've factored this out of signature.dart because 'coupling' & 'seperation of concerns'.
//        var reversedHash = Utils.HEX.encode(HEX.decode(hash).reversed.toList());

        // generate a signature for the input
        TransactionSignature sig = TransactionSignature.fromPrivateKey(signingKey);
        sig.setHashType(sigHashFlags);
        sig.createSignature(hash);

        UnlockingScriptBuilder scriptBuilder = input.getUnlockingScriptBuilder();

        if (scriptBuilder != null) {
            scriptBuilder.addSignature(sig);
        }else{
            throw new TransactionException("Trying to sign a Transaction Input that is missing a SignedUnlockBuilder");
        }

        return unsignedTxn; //signature has been added
    }

}
