package org.twostack.bitcoin.transaction;

import org.twostack.bitcoin.Sha256Hash;
import org.twostack.bitcoin.Utils;
import org.twostack.bitcoin.VarInt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Transaction {

    private long version;
    private long nLockTime = 0;
    private ArrayList<TransactionInput> inputs = new ArrayList<>();
    private ArrayList<TransactionOutput> outputs = new ArrayList<>();

    /// Max value for an unsigned 32 bit value
    static final long NLOCKTIME_MAX_VALUE = 4294967295L;

    /** Threshold for lockTime: below this value it is interpreted as block number, otherwise as timestamp. **/
    public static final int LOCKTIME_THRESHOLD = 500000000; // Tue Nov  5 00:53:20 1985 UTC

    /** FIXME: Same but as a BigInteger for CHECKLOCKTIMEVERIFY */
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
            output.setOutputIndex(i);
            outputs.add(output);
        }

        nLockTime = reader.readUint32();
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

    String uncheckedSerialize() throws IOException {

        ByteArrayOutputStream os = new ByteArrayOutputStream();

        // set the transaction version
        Utils.uint32ToByteStreamLE(version, os);

        // set the number of inputs
        VarInt varInt = new VarInt(inputs.size());
        os.write(varInt.encode());

        // write the inputs
        inputs.forEach( (input) ->  {
            try {
                os.write(input.serialize());
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

        return Utils.HEX.encode(os.toByteArray());
    }


    /** Returns an unmodifiable view of all inputs. */
    public List<TransactionInput> getInputs() {
        return Collections.unmodifiableList(inputs);
    }

    /** Returns an unmodifiable view of all outputs. */
    public List<TransactionOutput> getOutputs() {
        return Collections.unmodifiableList(outputs);
    }

}
