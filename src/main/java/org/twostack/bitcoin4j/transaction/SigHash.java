
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

import at.favre.lib.bytes.Bytes;
import org.twostack.bitcoin4j.*;
import org.twostack.bitcoin4j.exception.SigHashException;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptBuilder;
import org.twostack.bitcoin4j.script.ScriptChunk;
import org.twostack.bitcoin4j.script.ScriptOpCodes;

import javax.annotation.Nullable;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

public class SigHash {
    /// Do we accept signature using SIGHASH_FORKID
    ///
    static final int ENABLE_SIGHASH_FORKID = (1 << 16);

    /// Do we accept activate replay protection using a different fork id.
    ///
    static final int ENABLE_REPLAY_PROTECTION = (1 << 17);

    final byte[] _SIGHASH_SINGLE_BUG = "0000000000000000000000000000000000000000000000000000000000000001".getBytes();

    final String _BITS_64_ON = "ffffffffffffffff";

    private int _sigHashType;

    private Script _subScript;


    /**
     * <p>Calculates a signature hash, that is, a hash of a simplified form of the transaction. How exactly the transaction
     * is simplified is specified by the type and anyoneCanPay parameters.</p>
     *
     * <p>
     * When working with more complex transaction types and contracts, it can be necessary. When signing a P2SH output
     * the redeemScript should be the script encoded into the scriptSig field, for normal transactions, it's the
     * scriptPubKey of the output you're signing for.
     * </p>
     *
     * @param unsignedTxn - The transaction to calculate the signature has for
     * @param sigHashType - The bitwise combination of [SighashType] flags
     * @param inputIndex -  The input index in [txn] that the hash applies to
     * @param subscript - The portion of [SVScript] in the [TransactionOutput] of Spent [Transaction]
     *                   (after OP_CODESEPERATOR) that will be covered by the signature.
     * @param amount  - Amount in Satoshis. Used as part of ForkId calculation. Can be ZERO.
     */
    public byte[] createHash(Transaction unsignedTxn, int sigHashType, int inputIndex, Script subscript, BigInteger amount) throws IOException, SigHashException {
        /// [flags]       - The bitwise combination of [ScriptFlags] related to Sighash. Applies to BSV and BCH only,
        ///                 and refers to `ENABLE_SIGHASH_FORKID` and `ENABLE_REPLAY_PROTECTION`
        ///
        long flags = ENABLE_SIGHASH_FORKID;

        Transaction txnCopy = new Transaction(ByteBuffer.wrap(unsignedTxn.serialize()));

        Script subscriptCopy = new Script(subscript.getProgram()); //make a copy of subscript

        if ((flags & ENABLE_REPLAY_PROTECTION) > 0) {
            // Legacy chain's value for fork id must be of the form 0xffxxxx.
            // By xoring with 0xdead, we ensure that the value will be different
            // from the original one, even if it already starts with 0xff.
            int forkValue = sigHashType >> 8;
            int newForkValue = 0xff0000 | (forkValue ^ 0xdead);
            sigHashType = (newForkValue << 8) | (sigHashType & 0xff);
        }

        if (((sigHashType & SigHashType.FORKID.value) != 0) && (flags & ENABLE_SIGHASH_FORKID) != 0) {
            byte[] preImage = sigHashForForkid(txnCopy, sigHashType, inputIndex, subscriptCopy, amount);
            return Sha256Hash.hashTwice(preImage);
        }

        this._sigHashType = sigHashType;

        // For no ForkId sighash, separators need to be removed.
        this._subScript = removeCodeseparators(subscript);

        //blank out the txn input scripts
        for (TransactionInput input : txnCopy.getInputs()) {
            input.setScript(new ScriptBuilder().build());
        }

        //setup the input we wish to sign
        TransactionInput tmpInput = txnCopy.getInputs().get(inputIndex);
        TransactionInput replacementInput = new TransactionInput(tmpInput.getPrevTxnId(), tmpInput.getPrevTxnOutputIndex(), tmpInput.getSequenceNumber(), tmpInput.getUnlockingScriptBuilder());
        tmpInput.getUnlockingScriptBuilder().script = this._subScript;
        txnCopy.replaceInput(inputIndex, replacementInput);

        if ((sigHashType & 31) == SigHashType.NONE.value ||
                (sigHashType & 31) == SigHashType.SINGLE.value) {
            // clear all sequenceNumbers
            int ndx = 0;
            for(TransactionInput input : txnCopy.getInputs()){
                if (ndx != inputIndex ) {
                    txnCopy.getInputs().get(ndx).setSequenceNumber(0);
                }
                ndx++;
            };
        }

        if ((sigHashType & 31) == SigHashType.NONE.value) {
            txnCopy.clearOutputs();
        } else if ((sigHashType & 31) == SigHashType.SINGLE.value) {
            // The SIGHASH_SINGLE bug.
            // https://bitcointalk.org/index.php?topic=260595.0
            if (inputIndex >= txnCopy.getOutputs().size()) {

                // The input index is beyond the number of outputs, it's a buggy signature made by a broken
                // Bitcoin implementation. Bitcoin Core also contains a bug in handling this case:
                // any transaction output that is signed in this case will result in both the signed output
                // and any future outputs to this public key being steal-able by anyone who has
                // the resulting signature and the public key (both of which are part of the signed tx input).

                // Bitcoin Core's bug is that SignatureHash was supposed to return a hash and on this codepath it
                // actually returns the constant "1" to indicate an error, which is never checked for. Oops.
                return Sha256Hash.wrap("0100000000000000000000000000000000000000000000000000000000000000").getBytes();
            }

            // In SIGHASH_SINGLE the outputs after the matching input index are deleted, and the outputs before
            // that position are "nulled out". Unintuitively, the value in a "null" transaction is set to -1.
            List replacementOutputs = new ArrayList<>(txnCopy.getOutputs().subList(0, inputIndex + 1));
            txnCopy.clearOutputs(); //remove all the outputs
            txnCopy.addOutputs(replacementOutputs);
            //create new outputs up to inputIndex + 1
            for (int ndx = 0; ndx < inputIndex ; ndx++) {
                TransactionOutput output = new TransactionOutput(BigInteger.valueOf(Coin.NEGATIVE_SATOSHI.value), new ScriptBuilder().build());
                txnCopy.replaceOutput(ndx, output);
            }

            // The signature isn't broken by new versions of the transaction issued by other parties.
            for (int i = 0; i < txnCopy.getInputs().size(); i++){
                if (i != inputIndex)
                    txnCopy.getInputs().get(i).setSequenceNumber(0);
            }

        }

        if ((this._sigHashType & SigHashType.ANYONECANPAY.value) > 0) {
            TransactionInput keepInput = txnCopy.getInputs().get(inputIndex);
            txnCopy.clearInputs();
            txnCopy.addInput(keepInput);
        }

        //inline getHash()

        byte[] txnBytes= txnCopy.serialize(); //our copy of

        WriteUtils writer = new WriteUtils();
        writer.writeBytes(txnBytes, txnBytes.length);
        writer.writeUint32LE(this._sigHashType);

        byte[] preImage = writer.getBytes();

        return Sha256Hash.hashTwice(preImage);
    }


    /**
     * NOTE : DO NOT USE FOR SIGHASH CALCULATION. IT DOES NOT HANDLE SIGHASH_SINGLE BUG !!
     * Added here as convenience method for use with sCrypt Smart Contracting
     */
    public byte[] getSighashPreimage(Transaction unsignedTxn, int sigHashType, int inputIndex, Script subscript, BigInteger amount) throws IOException, SigHashException {

    /// [flags]       - The bitwise combination of [ScriptFlags] related to Sighash. Applies to BSV and BCH only,
        ///                 and refers to `ENABLE_SIGHASH_FORKID` and `ENABLE_REPLAY_PROTECTION`
        ///
        long flags = ENABLE_SIGHASH_FORKID;

        Transaction txnCopy = new Transaction(ByteBuffer.wrap(unsignedTxn.serialize()));

        Script subscriptCopy = new Script(subscript.getProgram()); //make a copy of subscript

        if ((flags & ENABLE_REPLAY_PROTECTION) > 0) {
            // Legacy chain's value for fork id must be of the form 0xffxxxx.
            // By xoring with 0xdead, we ensure that the value will be different
            // from the original one, even if it already starts with 0xff.
            int forkValue = sigHashType >> 8;
            int newForkValue = 0xff0000 | (forkValue ^ 0xdead);
            sigHashType = (newForkValue << 8) | (sigHashType & 0xff);
        }

        if (((sigHashType & SigHashType.FORKID.value) != 0) && (flags & ENABLE_SIGHASH_FORKID) != 0) {
            byte[] preImage = sigHashForForkid(txnCopy, sigHashType, inputIndex, subscriptCopy, amount);
            return preImage;
        }

        this._sigHashType = sigHashType;

        // For no ForkId sighash, separators need to be removed.
        this._subScript = removeCodeseparators(subscript);

        //blank out the txn input scripts
        for (TransactionInput input : txnCopy.getInputs()) {
            input.setScript(new ScriptBuilder().build());
        }

        //setup the input we wish to sign
        TransactionInput tmpInput = txnCopy.getInputs().get(inputIndex);
        TransactionInput replacementInput = new TransactionInput(tmpInput.getPrevTxnId(), tmpInput.getPrevTxnOutputIndex(), tmpInput.getSequenceNumber(), tmpInput.getUnlockingScriptBuilder());
        tmpInput.getUnlockingScriptBuilder().script = this._subScript;
        txnCopy.replaceInput(inputIndex, replacementInput);

        if ((sigHashType & 31) == SigHashType.NONE.value ||
                (sigHashType & 31) == SigHashType.SINGLE.value) {
            // clear all sequenceNumbers
            int ndx = 0;
            for(TransactionInput input : txnCopy.getInputs()){
                if (ndx != inputIndex ) {
                    txnCopy.getInputs().get(ndx).setSequenceNumber(0);
                }
                ndx++;
            };
        }

        if ((sigHashType & 31) == SigHashType.NONE.value) {
            txnCopy.clearOutputs();
        } else if ((sigHashType & 31) == SigHashType.SINGLE.value) {

            // The SIGHASH_SINGLE bug.
            // https://bitcointalk.org/index.php?topic=260595.0
            if (inputIndex >= txnCopy.getOutputs().size()) {

                // The input index is beyond the number of outputs, it's a buggy signature made by a broken
                // Bitcoin implementation. Bitcoin Core also contains a bug in handling this case:
                // any transaction output that is signed in this case will result in both the signed output
                // and any future outputs to this public key being steal-able by anyone who has
                // the resulting signature and the public key (both of which are part of the signed tx input).

                // Bitcoin Core's bug is that SignatureHash was supposed to return a hash and on this codepath it
                // actually returns the constant "1" to indicate an error, which is never checked for. Oops.
                return Sha256Hash.wrap("0100000000000000000000000000000000000000000000000000000000000000").getBytes();
            }

            // In SIGHASH_SINGLE the outputs after the matching input index are deleted, and the outputs before
            // that position are "nulled out". Unintuitively, the value in a "null" transaction is set to -1.
            List replacementOutputs = new ArrayList<>(txnCopy.getOutputs().subList(0, inputIndex + 1));
            txnCopy.clearOutputs(); //remove all the outputs
            txnCopy.addOutputs(replacementOutputs);
            //create new outputs up to inputIndex + 1
            for (int ndx = 0; ndx < inputIndex ; ndx++) {
                TransactionOutput output = new TransactionOutput(BigInteger.valueOf(Coin.NEGATIVE_SATOSHI.value), new ScriptBuilder().build());
                txnCopy.replaceOutput(ndx, output);
            }

            // The signature isn't broken by new versions of the transaction issued by other parties.
            for (int i = 0; i < txnCopy.getInputs().size(); i++){
                if (i != inputIndex)
                    txnCopy.getInputs().get(i).setSequenceNumber(0);
            }

        }

        if ((this._sigHashType & SigHashType.ANYONECANPAY.value) > 0) {
            TransactionInput keepInput = txnCopy.getInputs().get(inputIndex);
            txnCopy.clearInputs();
            txnCopy.addInput(keepInput);
        }

        //inline getHash()

        byte[] txnBytes= txnCopy.serialize(); //our copy of

        WriteUtils writer = new WriteUtils();
        writer.writeBytes(txnBytes, txnBytes.length);
        writer.writeUint32LE(this._sigHashType);

        byte[] preImage = writer.getBytes();

        return preImage;
    }



    private byte[] getPrevoutHash(Transaction tx) throws IOException {
        WriteUtils writer = new WriteUtils();

        for (TransactionInput input: tx.getInputs()){
            byte[] prevTxId = Utils.reverseBytes(input.getPrevTxnId());
            writer.writeBytes(prevTxId, prevTxId.length);
            writer.writeUint32LE(input.getPrevTxnOutputIndex());
        }

        byte[] buf = writer.getBytes();

        return Sha256Hash.hashTwice(buf);
    }

    private byte[] getSequenceHash(Transaction tx) throws IOException {
        WriteUtils writer = new WriteUtils();

        for (TransactionInput input: tx.getInputs()) {
            writer.writeUint32LE(input.getSequenceNumber());
        }

        byte[] buf = writer.getBytes();
        return Sha256Hash.hashTwice(buf);
    }

    private byte[] getOutputsHash(Transaction tx, @Nullable Integer n ) throws IOException {
        WriteUtils writer = new WriteUtils();

        if (n == null) {
            for(TransactionOutput output : tx.getOutputs()) {
                byte[] outputBytes = output.serialize();
                writer.writeBytes(outputBytes, outputBytes.length);
            }
        } else {
            byte[] outputBytes = tx.getOutputs().get(n).serialize();
            writer.writeBytes(outputBytes, outputBytes.length);
        }

        byte[] buf = writer.getBytes();
        return Sha256Hash.hashTwice(buf);
    }


//    public synchronized Sha256Hash hashForSignatureWitness( Transaction txn, int inputIndex, byte[] connectedScript, Coin prevValue, SigHashType type, boolean anyoneCanPay) {
    private byte[] sigHashForForkid(Transaction txnCopy, int sigHashType, int inputIndex, Script subscriptCopy, BigInteger satoshis) throws SigHashException, IOException {

        if (satoshis == null){
            throw new SigHashException("For ForkId=0 signatures, satoshis or complete input must be provided");
        }

        TransactionInput input = txnCopy.getInputs().get(inputIndex);

        byte[] hashPrevouts = new byte[32];
        byte[] hashSequence = new byte[32];
        byte[] hashOutputs = new byte[32];

        if (!((sigHashType & SigHashType.ANYONECANPAY.value) > 0)) {
            hashPrevouts = getPrevoutHash(txnCopy);
        }

        if (!((sigHashType & SigHashType.ANYONECANPAY.value) > 0) &&
                ((sigHashType & 31) != SigHashType.SINGLE.value) &&
                ((sigHashType & 31) != SigHashType.NONE.value)) {
            hashSequence = getSequenceHash(txnCopy);
        }

        if (((sigHashType & 31) != SigHashType.SINGLE.value) && ((sigHashType & 31) != SigHashType.NONE.value)) {
            hashOutputs = getOutputsHash(txnCopy, null);
        } else if (((sigHashType & 31) == SigHashType.SINGLE.value) && inputIndex < txnCopy.getOutputs().size()) {
            hashOutputs = getOutputsHash(txnCopy, inputIndex);
        }

        WriteUtils writer = new WriteUtils();

        // Version
        writer.writeUint32LE(txnCopy.getVersion());

        // Input prevouts/nSequence (none/all, depending on flags)
        writer.writeBytes(hashPrevouts, hashPrevouts.length);
        writer.writeBytes(hashSequence, hashSequence.length);

        //  outpoint (32-byte hash + 4-byte little endian)
        writer.writeBytes(Utils.reverseBytes(input.getPrevTxnId()), input.getPrevTxnId().length);
        writer.writeUint32LE(input.getPrevTxnOutputIndex());

        // scriptCode (subScript) from the UTXO (serialized as scripts inside CTxOuts)
        VarInt subscriptVarInt = new VarInt(subscriptCopy.getProgram().length);
        writer.writeBytes(subscriptVarInt.encode(), subscriptVarInt.encode().length);
        byte[] subscriptBytes = subscriptCopy.getProgram();
        writer.writeBytes(subscriptBytes, subscriptBytes.length);

        // value of the output spent by this input (8-byte little endian)
        writer.writeUint64LE(satoshis);

        // nSequence of the input (4-byte little endian)
        writer.writeUint32LE(input.getSequenceNumber());

        // Outputs (none/one/all, depending on flags)
        writer.writeBytes(hashOutputs, hashOutputs.length);

        // Locktime
        writer.writeUint32LE(txnCopy.getLockTime());

        // sighashType
        writer.writeUint32LE(sigHashType >> 0);

        byte[] buf = writer.getBytes();
        return buf;
//        byte[] hash = Sha256Hash.hashTwice(buf);
//
//        return hash;
    }


//    private byte[] getHash(Transaction txn) throws IOException {
//    }


    /// Strips all OP_CODESEPARATOR instructions from the script.
    // FIXME: Test if everything "AFTER" first SEPARATOR needs stripping, or just the SEPARATORS themselves
    Script removeCodeseparators(Script script) {
        List<ScriptChunk> newChunks = new ArrayList<ScriptChunk>();
        List<ScriptChunk> oldChunks = script.getChunks();
        for (int i = 0; i < oldChunks.size(); i++) {
            if (oldChunks.get(i).opcode != ScriptOpCodes.OP_CODESEPARATOR) {
                newChunks.add(oldChunks.get(i));
            }

            /* FIXME: Check if this needs to be activated. I.e. stop adding code once hitting first OP_CODESEPARATOR
            if (oldChunks.get(i).opcode == ScriptOpCodes.OP_CODESEPARATOR) {
                break;
            }
             */

        }

        return new Script(newChunks);
    }


}
