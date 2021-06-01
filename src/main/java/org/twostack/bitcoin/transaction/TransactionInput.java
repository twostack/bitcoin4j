package org.twostack.bitcoin.transaction;

import org.twostack.bitcoin.VarInt;
import org.twostack.bitcoin.script.Script;

import java.io.IOException;
import java.math.BigInteger;

public class TransactionInput {
   UnlockingScriptBuilder _scriptBuilder;

    /// Maximum size an unsigned int can be. Used as value of [sequenceNumber] when we
    /// want to indicate that the transaction's [Transaction.nLockTime] should be ignored.
    static int UINT_MAX =  0xFFFFFFFF;
//    private Boolean _isSignedInput = false;

    private long _sequenceNumber;

    private long _prevTxnOutputIndex;

    private byte[] _prevTxnId = new byte[32];

    private BigInteger _spendingAmount;

    private Script _scriptSig;

    public TransactionInput(byte[] prevTxnId, long prevTxnOutputIndex, Script scriptSig, long sequenceNumber){
        _prevTxnId = prevTxnId;
        _prevTxnOutputIndex = prevTxnOutputIndex;
        _scriptSig = scriptSig;
        _sequenceNumber = sequenceNumber;
    }

    public static TransactionInput fromByteArray(byte[] bytes) {
        return fromByteArray(bytes, null);
    }

    public static TransactionInput fromReader(ReadUtils reader){

        byte[] prevTxnId = reader.readBytes(32);
        long prevTxnOutputIndex = reader.readUint32();

        VarInt vi = reader.readVarInt();
        int scriptLength = vi.getOriginalSizeInBytes();

        Script scriptSig = new Script(reader.readBytes(scriptLength));
        long sequenceNumber = reader.readUint32();

        return new TransactionInput(prevTxnId, prevTxnOutputIndex, scriptSig, sequenceNumber);

    }

    public static TransactionInput fromByteArray(byte[] bytes, UnlockingScriptBuilder scriptBuilder) {

        ReadUtils rw = new ReadUtils(bytes);

        return fromReader(rw);
    }

    public byte[] serialize() throws IOException {

        WriteUtils wu = new WriteUtils();

        wu.writeBytes(_prevTxnId, 32);
        wu.writeUint32LE(_prevTxnOutputIndex);

        byte[] scriptBytes = _scriptSig.getProgram();
        VarInt vi = new VarInt(scriptBytes.length);

        wu.writeBytes(vi.encode(), 0);
        wu.writeBytes(scriptBytes, 0);

        wu.writeUint32LE(_sequenceNumber);

        return wu.getBytes();
    }
}
