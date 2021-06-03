package org.twostack.bitcoin.transaction;

import org.twostack.bitcoin.VarInt;
import org.twostack.bitcoin.script.Script;
import org.twostack.bitcoin.script.ScriptBuilder;

import java.io.IOException;
import java.math.BigInteger;

public class TransactionOutput {

    private BigInteger satoshis = BigInteger.ZERO;

//    private int outputIndex;

    private LockingScriptBuilder _lockingScriptBuilder;

    public static TransactionOutput fromReader(ReadUtils reader) {

        BigInteger satoshis = reader.readUint64();
        int size = reader.readVarInt().intValue();
        Script script;
        if (size != 0) {
            script = Script.fromByteArray(reader.readBytes(size)); //FIXME: ensure a copy is taken
        } else {
            script = new ScriptBuilder().build();
        }

        return new TransactionOutput(satoshis, script);
    }

    TransactionOutput(BigInteger satoshis, LockingScriptBuilder builder){
        this.satoshis = satoshis;
        this._lockingScriptBuilder = builder;
    }


    /// The default constructor. Initializes a "clean slate" output.
    TransactionOutput(BigInteger satoshis, Script script){
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

//    public int getOutputIndex() {
//        return outputIndex;
//    }
//
//    public void setOutputIndex(int outputIndex) {
//        this.outputIndex = outputIndex;
//    }

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
