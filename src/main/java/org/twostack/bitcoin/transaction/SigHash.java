package org.twostack.bitcoin.transaction;

import org.twostack.bitcoin.Sha256Hash;
import org.twostack.bitcoin.Utils;
import org.twostack.bitcoin.VarInt;
import org.twostack.bitcoin.exception.SigHashException;
import org.twostack.bitcoin.script.Script;
import org.twostack.bitcoin.script.ScriptBuilder;
import org.twostack.bitcoin.script.ScriptChunk;
import org.twostack.bitcoin.script.ScriptOpCodes;

import javax.annotation.Nullable;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
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


    /* Calculates the hash value according to the Sighash flags specified in [sighashType]
    ///
    /// [unsignedTxn] - The transaction to calculate the signature has for
    ///
    /// [sighashType] - The bitwise combination of [SighashType] flags
    ///
    /// [inputNumber] - The input index in [txn] that the hash applies to
    ///
    /// [subscript]   - The portion of [SVScript] in the [TransactionOutput] of Spent [Transaction]
    ///                 (after OP_CODESEPERATOR) that will be covered by the signature.
    ///
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

        if (((sigHashType & SigHashType.FORKID.byteValue()) != 0) && (flags & ENABLE_SIGHASH_FORKID) != 0) {
            return sigHashForForkid(txnCopy, sigHashType, inputIndex, subscriptCopy, amount);
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

        //txnCopy.serialize(false); //FIXME: why are we serializing ? what side-effect is triggered here on internal state ?

        if ((sigHashType & 31) == SigHashType.NONE.byteValue() ||
                (sigHashType & 31) == SigHashType.SINGLE.byteValue()) {
            // clear all sequenceNumbers
            int ndx = 0;
            for(TransactionInput input : txnCopy.getInputs()){
                if (ndx != inputIndex ) {
                    txnCopy.getInputs().get(ndx).setSequenceNumber(0);
                }
                ndx++;
            };
        }

        if ((sigHashType & 31) == SigHashType.NONE.byteValue()) {
            txnCopy.clearOutputs();
        } else if ((sigHashType & 31) == SigHashType.SINGLE.byteValue()) {
            // The SIGHASH_SINGLE bug.
            // https://bitcointalk.org/index.php?topic=260595.0
            if (inputIndex >= txnCopy.getOutputs().size()) {
                return _SIGHASH_SINGLE_BUG;
            }

            TransactionOutput output = txnCopy.getOutputs().get(inputIndex);
            TransactionOutput txout = new TransactionOutput(output.getAmount(), output.getScript());

            //resize outputs to current size of inputIndex + 1

            int outputCount = inputIndex + 1;
            txnCopy.clearOutputs(); //remove all the outputs
            //create new outputs up to inputIndex + 1
            for (int ndx = 0; ndx < inputIndex + 1; ndx++) {
                //FIXME: What's going on here ?
                TransactionOutput tx = new TransactionOutput(new BigInteger(_BITS_64_ON, 16), new ScriptBuilder().build());
                txnCopy.addOutput(tx);
            }

            //add back the saved output in the corresponding position of inputIndex
            txnCopy.replaceOutput(inputIndex, txout); //FIXME : ??? Is this the correct way ?
        }

        if ((this._sigHashType & SigHashType.ANYONECANPAY.byteValue()) > 0) {
            TransactionInput keepInput = txnCopy.getInputs().get(inputIndex);
            txnCopy.clearInputs();
            txnCopy.addInput(keepInput);
        }

        return getHash(txnCopy);
    }


    private byte[] getPrevoutHash(Transaction tx) throws IOException {
        WriteUtils writer = new WriteUtils();

        for (TransactionInput input: tx.getInputs()){
            byte[] prevTxId = input.getPrevTxnId();
            writer.writeBytes(prevTxId, prevTxId.length); //FIXME: This was reversed. LE ?
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


    private byte[] sigHashForForkid(Transaction txnCopy, int sigHashType, int inputIndex, Script subscriptCopy, BigInteger satoshis) throws SigHashException, IOException {

        if (satoshis == null){
            throw new SigHashException("For ForkId=0 signatures, satoshis or complete input must be provided");
        }

        TransactionInput input = txnCopy.getInputs().get(inputIndex);

        byte[] hashPrevouts = new byte[32];
        byte[] hashSequence = new byte[32];
        byte[] hashOutputs = new byte[32];

        if (!((sigHashType & SigHashType.ANYONECANPAY.byteValue()) > 0)) {
            hashPrevouts = getPrevoutHash(txnCopy);
        }

        if (!((sigHashType & SigHashType.ANYONECANPAY.byteValue()) > 0) &&
                ((sigHashType & 31) != SigHashType.SINGLE.byteValue()) &&
                ((sigHashType & 31) != SigHashType.NONE.byteValue())) {
            hashSequence = getSequenceHash(txnCopy);
        }

        if (((sigHashType & 31) != SigHashType.SINGLE.byteValue()) && ((sigHashType & 31) != SigHashType.NONE.byteValue())) {
            hashOutputs = getOutputsHash(txnCopy, null);
        } else if (((sigHashType & 31) == SigHashType.SINGLE.byteValue()) && inputIndex < txnCopy.getOutputs().size()) {
            hashOutputs = getOutputsHash(txnCopy, inputIndex);
        }

        WriteUtils writer = new WriteUtils();

        // Version
        writer.writeUint32LE(txnCopy.getVersion());

        // Input prevouts/nSequence (none/all, depending on flags)
        writer.writeBytes(hashPrevouts, hashPrevouts.length);
        writer.writeBytes(hashSequence, hashSequence.length);

        //  outpoint (32-byte hash + 4-byte little endian)
        writer.writeBytes(input.getPrevTxnId(), input.getPrevTxnId().length);
        writer.writeUint32LE(input.getPrevTxnOutputIndex());

        // scriptCode of the input (serialized as scripts inside CTxOuts)
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
        return Sha256Hash.hashTwice(buf);
    }


    private byte[] getHash(Transaction txn) throws IOException {
        byte[] txnBytes= txn.serialize(); //our copy of

        WriteUtils writer = new WriteUtils();
        writer.writeBytes(txnBytes, txnBytes.length);
        writer.writeUint32LE(this._sigHashType);

        return Sha256Hash.hashTwice(writer.getBytes()); //FIXME: Used to reverse this
    }


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
