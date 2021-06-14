
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

import org.twostack.bitcoin4j.VarInt;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptBuilder;

import java.io.IOException;
import java.math.BigInteger;

public class TransactionOutput {

    private BigInteger satoshis = BigInteger.ZERO;

    private LockingScriptBuilder _lockingScriptBuilder;

    public static TransactionOutput fromReader(ReadUtils reader) {

        BigInteger satoshis = reader.readUint64();
        int size = reader.readVarInt().intValue();
        Script script;
        if (size != 0) {
            script = Script.fromByteArray(reader.readBytes(size));
        } else {
            script = new ScriptBuilder().build();
        }

        return new TransactionOutput(satoshis, script);
    }

    TransactionOutput(BigInteger satoshis, LockingScriptBuilder builder){
        this.satoshis = satoshis;
        this._lockingScriptBuilder = builder;
    }

    public TransactionOutput(BigInteger satoshis, Script script){
        this.satoshis = satoshis;
        this._lockingScriptBuilder = new DefaultLockBuilder(script);
    }

    public static TransactionOutput fromByteBuffer(byte[] buffer) {

        ReadUtils reader = new ReadUtils(buffer);

        return fromReader(reader);

    }

    /// Returns a byte array containing the raw transaction output
    public byte[] serialize() throws IOException {
        WriteUtils writer = new WriteUtils();

        //write satoshi value
        writer.writeUint64LE(satoshis);

        //write the locking script
        byte[] outputScript = _lockingScriptBuilder.getScriptPubkey().getProgram();
        VarInt varInt = new VarInt(outputScript.length);
        byte[] varIntBytes = varInt.encode();
        writer.writeBytes(varIntBytes, varIntBytes.length);

        writer.writeBytes(outputScript, outputScript.length);
        return writer.getBytes();
    }

    public Script getScript() {
        return _lockingScriptBuilder.getScriptPubkey();
    }

    public BigInteger getAmount() {
        return satoshis;
    }
    public void setAmount(BigInteger amount) {
        this.satoshis = amount;
    }
}
