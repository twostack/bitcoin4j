
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

import org.twostack.bitcoin4j.Sha256Hash;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.VarInt;
import org.twostack.bitcoin4j.script.Script;

import java.io.IOException;
import java.util.Arrays;

public class TransactionInput {

    /*
        Maximum size an unsigned long can be. Used as value of [sequenceNumber] when we
        want to indicate that the transaction's [Transaction.nLockTime] should be ignored.
        This is a 64-bit value, in range 0 to (2^64) - 1
     */
    static long MAX_SEQ_NUMBER =  0xFFFFFFFFL;

    private long _sequenceNumber;

    private long _prevTxnOutputIndex;

    private byte[] _prevTxnId = new byte[32];

    private UnlockingScriptBuilder _unlockingScriptBuilder;

    public TransactionInput(byte[] prevTxnId, long prevTxnOutputIndex, long sequenceNumber, UnlockingScriptBuilder unlocker){
        _prevTxnId = prevTxnId;
        _prevTxnOutputIndex = prevTxnOutputIndex;
        _sequenceNumber = sequenceNumber;
        _unlockingScriptBuilder = unlocker;

    }

    public static TransactionInput fromReader(ReadUtils reader){

        byte[] prevTxnId = Utils.reverseBytes(reader.readBytes(32));
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

        wu.writeBytes(Utils.reverseBytes(_prevTxnId), 32);
        wu.writeUint32LE(_prevTxnOutputIndex);

        byte[] scriptBytes = _unlockingScriptBuilder.getScriptSig().getProgram();
        VarInt vi = new VarInt(scriptBytes.length);

        wu.writeBytes(vi.encode(), vi.getSizeInBytes());
        wu.writeBytes(scriptBytes, scriptBytes.length);

        wu.writeUint32LE(_sequenceNumber);

        return wu.getBytes();
    }

    /**
     * Coinbase transactions have special inputs with hashes of zero. If this is such an input, returns true.
     */
    public boolean isCoinBase() {
        return Arrays.equals(_prevTxnId, Sha256Hash.ZERO_HASH.getBytes() ) &&
                (_prevTxnOutputIndex & 0xFFFFFFFFL) == 0xFFFFFFFFL;  // -1 but all is serialized to the wire as unsigned int.
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

    public boolean isFinal() {
        return _sequenceNumber != MAX_SEQ_NUMBER;
    }

    public void setPrevTxnOutputIndex(int i) {
        this._prevTxnOutputIndex = i;
    }
}
