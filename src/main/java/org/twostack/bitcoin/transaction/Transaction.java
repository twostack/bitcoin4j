package org.twostack.bitcoin.transaction;

import com.google.common.math.LongMath;
import org.twostack.bitcoin.Sha256Hash;
import org.twostack.bitcoin.Utils;
import org.twostack.bitcoin.VarInt;
import org.twostack.bitcoin.exception.TransactionException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;

public class Transaction {


    private long version = 1;
    private long nLockTime = 0;
    private ArrayList<TransactionInput> inputs = new ArrayList<>();
    private ArrayList<TransactionOutput> outputs = new ArrayList<>();

    /// Max value for an unsigned 32 bit value
    public static final long NLOCKTIME_MAX_VALUE = 4294967295L;

    public static final long MAX_COINS = 21000000;
    /// max amount of satoshis in circulation

    private static final int SMALLEST_UNIT_EXPONENT = 8;
    private static final long COIN_VALUE = LongMath.pow(10, SMALLEST_UNIT_EXPONENT);

    public static final long MAX_MONEY = LongMath.checkedMultiply(COIN_VALUE, MAX_COINS);

    /** Threshold for lockTime: below this value it is interpreted as block number, otherwise as timestamp. **/
    public static final int LOCKTIME_THRESHOLD = 500000000; // Tue Nov  5 00:53:20 1985 UTC

    /** TODO: Same but as a BigInteger for CHECKLOCKTIMEVERIFY */
    public static final BigInteger LOCKTIME_THRESHOLD_BIG = BigInteger.valueOf(LOCKTIME_THRESHOLD);

    /** How many bytes a transaction can be before it won't be relayed anymore. Currently 100kb. */
    public static final int MAX_STANDARD_TX_SIZE = 100000;

    private ByteBuffer txHash;


    public Transaction(){

    }

    /*
    Creates a Transaction from an array of bytes
     */
    public Transaction(ByteBuffer buffer){

        byte[] hash = Sha256Hash.hashTwice(buffer.array());
        txHash = ByteBuffer.wrap(hash);
        parseBuffer(buffer);
    }

    /// Constructs a  transaction instance from the raw hexadecimal string.
    public static Transaction fromHex(String txnHex) {

        byte[] bytes = Utils.HEX.decode(txnHex);
        byte[] hash = Sha256Hash.hashTwice(Utils.HEX.decode(txnHex));
        ByteBuffer buffer = ByteBuffer.wrap(bytes);

        return new Transaction(buffer);
    }

    private void parseBuffer(ByteBuffer buffer){

        ReadUtils reader = new ReadUtils(buffer.array());

        Integer i, sizeTxIns, sizeTxOuts;

        version = reader.readUint32();
        sizeTxIns = reader.readVarInt().intValue();
        for (i = 0; i < sizeTxIns; i++) {
            TransactionInput input = TransactionInput.fromReader(reader);
            inputs.add(input);
        }

        sizeTxOuts = reader.readVarInt().intValue();
        for (i = 0; i < sizeTxOuts; i++) {
            TransactionOutput output = TransactionOutput.fromReader(reader);
//            output.setOutputIndex(i); //FIXME: What are implications of tracking output index elsewhere ?
            outputs.add(output);
        }

        nLockTime = reader.readUint32();
    }

    byte[] serialize() throws IOException {

        ByteArrayOutputStream os = new ByteArrayOutputStream();

        // set the transaction version
        Utils.uint32ToByteStreamLE(version, os);

        // set the number of inputs
        VarInt varInt = new VarInt(inputs.size());
        os.write(varInt.encode());

        // write the inputs
        inputs.forEach( (input) ->  {
            try {
                byte[] buf = input.serialize();
                os.write(buf);

            }catch(IOException ex){
                System.out.println(ex.getMessage()); //FIXME: !!
            }
        });

        //set the number of outputs to come
        varInt = new VarInt(outputs.size());
        os.write(varInt.encode());

        // write the outputs
        outputs.forEach((output) -> {
            try {
                os.write(output.serialize());
            }catch(IOException ex){
                System.out.println(ex.getMessage()); //FIXME: !!!
            }
        });

        // write the locktime
        Utils.uint32ToByteStreamLE(nLockTime, os);

        return os.toByteArray();
    }


    /** Returns an unmodifiable view of all inputs. */
    public List<TransactionInput> getInputs() {
        return Collections.unmodifiableList(inputs);
    }

    public void replaceOutput(int index, TransactionOutput txout) {
        outputs.set(index, txout);
    }

    public TransactionInput replaceInput(int index, TransactionInput input){
        return inputs.set(index, input);
    }

    public void clearInputs() {
        inputs.clear();
    }

    public void clearOutputs() {
        outputs.clear();
    }

    /** Returns an unmodifiable view of all outputs. */
    public List<TransactionOutput> getOutputs() {
        return Collections.unmodifiableList(outputs);
    }

    public String getTransactionId(){
        if (txHash == null){
            return "";
        }

        return Utils.HEX.encode(txHash.array());
    }

    public byte[] getTransactionIdBytes(){
        if (txHash == null){
            return new byte[]{};
        }

        return txHash.array();
    }

    public void addOutput(TransactionOutput output) {
        outputs.add(output);
    }

    public void addInput(TransactionInput input) {
        inputs.add(input);
    }

    public long getVersion() {
        return version;
    }

    public long getLockTime() {
        return nLockTime;
    }

    public void setLockTime(long nLockTime) {
        this.nLockTime = nLockTime;
    }

    public void addInputs(List<TransactionInput> inputs) {
        this.inputs.addAll(inputs);
    }

    public void addOutputs(List<TransactionOutput> outputs) {
        this.outputs.addAll(outputs);
    }
}
