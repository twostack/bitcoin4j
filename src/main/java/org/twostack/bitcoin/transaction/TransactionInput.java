package org.twostack.bitcoin.transaction;

import org.twostack.bitcoin.VarInt;
import org.twostack.bitcoin.script.Script;

import java.io.IOException;
import java.math.BigInteger;

public class TransactionInput {

    /// Maximum size an unsigned int can be. Used as value of [sequenceNumber] when we
    /// want to indicate that the transaction's [Transaction.nLockTime] should be ignored.
    static int UINT_MAX =  0xFFFFFFFF;
//    private Boolean _isSignedInput = false;

    private long _sequenceNumber;

    private long _prevTxnOutputIndex;

    private byte[] _prevTxnId = new byte[32];

    private UnlockingScriptBuilder _unlockingScriptBuilder;

    public TransactionInput(byte[] prevTxnId, long prevTxnOutputIndex, long sequenceNumber, UnlockingScriptBuilder unlocker){
        _prevTxnId = prevTxnId;
        _prevTxnOutputIndex = prevTxnOutputIndex;
//        _scriptSig = unlocker.getScriptSig();
        _sequenceNumber = sequenceNumber;
        _unlockingScriptBuilder = unlocker;

    }

    public static TransactionInput fromReader(ReadUtils reader){

        byte[] prevTxnId = reader.readBytes(32); //FIXME: Reverse this to get LE
        long prevTxnOutputIndex = reader.readUint32();

        VarInt vi = reader.readVarInt();
        int scriptLength = vi.intValue();

        Script scriptSig = new Script(reader.readBytes(scriptLength));
        long sequenceNumber = reader.readUint32();

        return new TransactionInput(prevTxnId, prevTxnOutputIndex, sequenceNumber, new DefaultUnlockBuilder(scriptSig));

    }

    public static TransactionInput fromByteArray(byte[] bytes) {

        ReadUtils rw = new ReadUtils(bytes);

        return fromReader(rw);
    }

    public byte[] serialize() throws IOException {

        WriteUtils wu = new WriteUtils();

        wu.writeBytes(_prevTxnId, 32);
        wu.writeUint32LE(_prevTxnOutputIndex);

        byte[] scriptBytes = _unlockingScriptBuilder.getScriptSig().getProgram();
        VarInt vi = new VarInt(scriptBytes.length);

        wu.writeBytes(vi.encode(), vi.getSizeInBytes());
        wu.writeBytes(scriptBytes, scriptBytes.length);

        wu.writeUint32LE(_sequenceNumber);

        return wu.getBytes();
    }

    public long getSequenceNumber() {
        return _sequenceNumber;
    }

    public long getPrevTxnOutputIndex() {
        return _prevTxnOutputIndex;
    }

    public byte[] getPrevTxnId() {
        return _prevTxnId;
    }

    public Script getScriptSig() {
        return _unlockingScriptBuilder.getScriptSig();
    }

    public UnlockingScriptBuilder getUnlockingScriptBuilder() {
        return _unlockingScriptBuilder;
    }

    public void setScript(Script script) {
        this._unlockingScriptBuilder.script = script;
    }

    public void setSequenceNumber(long i) {
        this._sequenceNumber = i;
    }
}
