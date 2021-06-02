package org.twostack.bitcoin.transaction;

import org.twostack.bitcoin.VarInt;
import org.twostack.bitcoin.script.Script;
import org.twostack.bitcoin.script.ScriptBuilder;
import org.twostack.bitcoin.script.ScriptChunk;

import javax.annotation.Nullable;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;

public class TransactionOutput {

    private BigInteger satoshis = BigInteger.ZERO;


    private String transactionId;
    private int outputIndex;

    private Script script;

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

    /// The default constructor. Initializes a "clean slate" output.
    TransactionOutput(BigInteger satoshis, Script script){
        this.satoshis = satoshis;
        this.script = script;
    }

    public static TransactionOutput fromByteBuffer(byte[] buffer) {

        ReadUtils reader = new ReadUtils(buffer);

        return fromReader(reader);

    }

//    ///Returns true is satoshi amount if outside of valid range
//    ///
//    /// See [Transaction.MAX_MONEY]
//    bool invalidSatoshis() {
//        //    if (this._satoshis > MAX_SAFE_INTEGER) {
//        if (this._satoshis < BigInt.zero)
//            return true;
//
//        if (this._satoshis > Transaction.MAX_MONEY) //yes, there is a finite amount of bitcoin
//            return true;
//
//        return false;
//    }

    /// Returns a byte array containing the raw transaction output
    public byte[] serialize() throws IOException {
        WriteUtils writer = new WriteUtils();

        //write satoshi value
        writer.writeUint64LE(satoshis);

        //write the locking script
        byte[] outputScript = script.getProgram();
        VarInt varInt = new VarInt(outputScript.length);
        byte[] varIntBytes = varInt.encode();
        writer.writeBytes(varIntBytes, varIntBytes.length);

        writer.writeBytes(outputScript, outputScript.length);
        return writer.getBytes();
    }

    public int getOutputIndex() {
        return outputIndex;
    }

    public void setOutputIndex(int outputIndex) {
        this.outputIndex = outputIndex;
    }

    public String getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }
}
