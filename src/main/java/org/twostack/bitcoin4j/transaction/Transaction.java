
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

import com.google.common.math.LongMath;
import org.twostack.bitcoin4j.Sha256Hash;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.VarInt;
import org.twostack.bitcoin4j.exception.VerificationException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
    /// max amount of bitcoins in circulation

    private static final int SMALLEST_UNIT_EXPONENT = 8;
    private static final long COIN_VALUE = LongMath.pow(10, SMALLEST_UNIT_EXPONENT);

    public static final long MAX_MONEY = LongMath.checkedMultiply(COIN_VALUE, MAX_COINS);

    /** Threshold for lockTime: below this value it is interpreted as block number, otherwise as timestamp. **/
    public static final int LOCKTIME_THRESHOLD = 500000000; // Tue Nov  5 00:53:20 1985 UTC

    /** TODO: Same but as a BigInteger for CHECKLOCKTIMEVERIFY */
    public static final BigInteger LOCKTIME_THRESHOLD_BIG = BigInteger.valueOf(LOCKTIME_THRESHOLD);

    /** How many bytes a transaction can be before it won't be relayed anymore. Currently 100kb. */
    public static final int MAX_STANDARD_TX_SIZE = 100000;

    public Transaction(){

    }

    /*
    Creates a Transaction from an array of bytes
     */
    public Transaction(ByteBuffer buffer){

        byte[] hash = Sha256Hash.hashTwice(buffer.array());
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

    public byte[] serialize() throws IOException {

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


    /**
     * <p>Checks the transaction contents for sanity, in ways that can be done in a standalone manner.
     * Does <b>not</b> perform all checks on a transaction such as whether the inputs are already spent.
     * Specifically this method verifies:</p>
     *
     * <ul>
     *     <li>That there is at least one input and output.</li>
     *     <li>That the serialized size is not larger than the max block size.</li>
     *     <li>That no outputs have negative value.</li>
     *     <li>That the outputs do not sum to larger than the max allowed quantity of coin in the system.</li>
     *     <li>If the tx is a coinbase tx, the coinbase scriptSig size is within range. Otherwise that there are no
     *     coinbase inputs in the tx.</li>
     * </ul>
     *
     * @throws VerificationException
     */
    public void verify() throws VerificationException {

        if (inputs.size() == 0 || outputs.size() == 0)
            throw new VerificationException.EmptyInputsOrOutputs();


        List<String> outpoints = new ArrayList<>();
        for (TransactionInput input : inputs) {

            String outpointId = Utils.HEX.encode(input.getPrevTxnId()) + ":" + input.getPrevTxnOutputIndex();

            if (outpoints.contains(outpointId)){
                throw new VerificationException.DuplicatedOutPoint();
            }

            outpoints.add(outpointId);
        }

        BigInteger valueOut = BigInteger.ZERO;
        for (TransactionOutput output : outputs) {
            BigInteger value = output.getAmount();
            if (value.signum() < 0)
                throw new VerificationException.NegativeValueOutput();
            try {
                valueOut = valueOut.add(value);
            } catch (ArithmeticException e) {
                throw new VerificationException.ExcessiveValue();
            }
            if (valueOut.compareTo(BigInteger.valueOf(MAX_MONEY)) == 1)
                throw new VerificationException.ExcessiveValue();
        }


        if (isCoinBase()) {
            int progLength = inputs.get(0).getScriptSig().getProgram().length;
            if (progLength < 2 ||  progLength > 100)
                throw new VerificationException.CoinbaseScriptSizeOutOfRange();
        } else {
            for (TransactionInput input : inputs)
                if (input.isCoinBase())
                    throw new VerificationException.UnexpectedCoinbaseInput();
        }
    }


    /**
     * A coinbase transaction is one that creates a new coin. They are the first transaction in each block and their
     * value is determined by a formula that all implementations of Bitcoin share. In 2011 the value of a coinbase
     * transaction is 50 coins, but in future it will be less. A coinbase transaction is defined not only by its
     * position in a block but by the data in the inputs.
     */
    public boolean isCoinBase() {
        return inputs.size() == 1 && inputs.get(0).isCoinBase();
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
        byte[] idBytes = getTransactionIdBytes();
        return Utils.HEX.encode(Utils.reverseBytes(idBytes));
    }

    public byte[] getTransactionIdBytes(){

        byte[] rawTx = new byte[]{};
        try {
            rawTx = this.serialize();
        }catch(IOException ex){

        }

        return Sha256Hash.hashTwice(rawTx);
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
