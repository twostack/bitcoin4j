
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

import org.twostack.bitcoin4j.Address;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.exception.SigHashException;
import org.twostack.bitcoin4j.exception.SignatureDecodeException;
import org.twostack.bitcoin4j.exception.TransactionException;
import org.twostack.bitcoin4j.script.Script;

import javax.annotation.Nullable;
import java.io.IOException;
import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.twostack.bitcoin4j.Utils.HEX;

public class TransactionBuilder {

    private List<TransactionInput> inputs = new ArrayList<>();
    private List<TransactionOutput> outputs = new ArrayList<>();

    //Map the transactionIds we're spending from, to the corresponding UTXO amount in the output
    private Map<String, BigInteger> spendingMap = new HashMap();

    private LockingScriptBuilder changeScriptBuilder;
    private BigInteger changeAmount = BigInteger.ZERO;

    public TransactionOutput changeOutput;

    private final long DEFAULT_FEE_PER_KB = 512; //amount in satoshis

    static final BigInteger DUST_AMOUNT = BigInteger.valueOf(256);

    /// Margin of error to allow fees in the vicinity of the expected value but doesn't allow a big difference
    private static final BigInteger FEE_SECURITY_MARGIN = BigInteger.valueOf(150);

    private long feePerKb = DEFAULT_FEE_PER_KB;

    private BigInteger transactionFee;

    private boolean changeScriptFlag = false;

    private Set<TransactionOption> transactionOptions = new HashSet<TransactionOption>();


    /// Safe upper bound for change address script size in bytes
    static final int CHANGE_OUTPUT_MAX_SIZE = 20 + 4 + 34 + 4;
    static final int MAXIMUM_EXTRA_SIZE = 4 + 9 + 9 + 4;
    static final int SCRIPT_MAX_SIZE = 149;

    private long nLockTime = 0;

    private HashMap<String, SignerDto> signerMap = new HashMap();


    private class SignerDto{
        private TransactionSigner signer;
        private TransactionOutpoint outpoint;

        private SignerDto(){}

        SignerDto(TransactionSigner signer, TransactionOutpoint outpoint){
            this.signer = signer;
            this.outpoint = outpoint;
        }

        public TransactionSigner getSigner() {
            return signer;
        }

        public TransactionOutpoint getOutpoint() {
            return outpoint;
        }
    }


    /**
     utxoMap is expected to have :

     {
     "transactionId" : [String],
     "satoshis", [BigInteger],
     "sequenceNumber", [long],
     "outputIndex", [int],
     "scriptPubKey", [String]
     }
     */
    public TransactionBuilder spendFromUtxoMap(TransactionSigner signer, Map<String, Object> utxoMap, @Nullable  UnlockingScriptBuilder unlocker){

        String transactionId = (String) utxoMap.get("transactionId");

        int outputIndex = (int ) utxoMap.get("outputIndex");
        long sequenceNumber = (long) utxoMap.get("sequenceNumber");

        TransactionOutpoint outpoint = new TransactionOutpoint();
        outpoint.setOutputIndex(outputIndex);
        outpoint.setLockingScript(Script.fromAsmString((String)utxoMap.get("scriptPubKey")));
        outpoint.setSatoshis((BigInteger)utxoMap.get("satoshis"));
        outpoint.setTransactionId(transactionId);

        String mapKey = transactionId + ":" + outputIndex;

        this.signerMap.put(mapKey, new SignerDto(signer, outpoint));

        if (unlocker == null){
            unlocker = new DefaultUnlockBuilder();
        }

        TransactionInput input = new TransactionInput(
                HEX.decode((String)utxoMap.get("transactionId")),
                outputIndex,
                sequenceNumber,
                unlocker
        );

        spendingMap.put(mapKey, (BigInteger) utxoMap.get("satoshis"));

        inputs.add(input);

        return this;
    }

    /**
        utxoMap is expected to have :

        {
            "transactionId" : [String],
            "satoshis", [BigInteger],
            "sequenceNumber", [long],
            "outputIndex", [int],
            "scriptPubKey", [String]
        }
     */
    public TransactionBuilder spendFromUtxoMap(Map<String, Object> utxoMap, @Nullable  UnlockingScriptBuilder unlocker) {

        int outputIndex = (int ) utxoMap.get("outputIndex");
        long sequenceNumber = (long) utxoMap.get("sequenceNumber");
//        Script scriptPubKey = new Script(HEX.decode((String) utxoMap.get("scriptPubKey")));

        if (unlocker == null){
            unlocker = new DefaultUnlockBuilder();
        }

        TransactionInput input = new TransactionInput(
                HEX.decode((String)utxoMap.get("transactionId")),
                outputIndex,
                sequenceNumber,
                unlocker
        );

        String mapKey = (String) utxoMap.get("transactionId") + ":" + outputIndex;
        spendingMap.put(mapKey, (BigInteger) utxoMap.get("satoshis"));

        inputs.add(input);

        return this;

    }

    public TransactionBuilder spendFromTransaction(TransactionSigner signer, Transaction txn, int outputIndex, long sequenceNumber, UnlockingScriptBuilder unlocker){

        //save the transactionId. This is expensive operation which serialises the Tx.
        String transactionId = txn.getTransactionId();

        //construct the data to save to signerMap
        TransactionOutput output = txn.getOutputs().get(outputIndex);

        TransactionOutpoint outpoint = new TransactionOutpoint();
        outpoint.setOutputIndex(outputIndex);
        outpoint.setLockingScript(output.getScript());
        outpoint.setSatoshis(output.getAmount());
        outpoint.setTransactionId(transactionId);

        String mapKey = transactionId + ":" + outputIndex;
        this.signerMap.put(mapKey, new SignerDto(signer, outpoint));

        //update the spending transactionInput
        TransactionInput input = new TransactionInput(
                Utils.reverseBytes(txn.getTransactionIdBytes()),
                outputIndex,
                sequenceNumber,
                unlocker
        );

        spendingMap.put(mapKey, txn.getOutputs().get(outputIndex).getAmount());

        inputs.add(input);
        return this;
    }

    public TransactionBuilder spendFromTransaction(Transaction txn, int outputIndex, long sequenceNumber, UnlockingScriptBuilder unlocker){

        TransactionInput input = new TransactionInput(
                Utils.reverseBytes(txn.getTransactionIdBytes()),
                outputIndex,
                sequenceNumber,
                unlocker
        );

        String mapKey = txn.getTransactionId() + ":" + outputIndex;
        spendingMap.put(mapKey, txn.getOutputs().get(outputIndex).getAmount());

        inputs.add(input);
        return this;

    }

    public TransactionBuilder spendFromOutpoint(TransactionSigner signer, TransactionOutpoint outpoint, long sequenceNumber, UnlockingScriptBuilder unlocker) {

        String mapKey = outpoint.getTransactionId() + ":" + outpoint.getOutputIndex();
        this.signerMap.put(mapKey, new SignerDto(signer, outpoint));

        TransactionInput input = new TransactionInput(
                HEX.decode(outpoint.getTransactionId()),
                outpoint.getOutputIndex(),
                sequenceNumber,
                unlocker
        );

        spendingMap.put(mapKey, outpoint.getSatoshis());

        inputs.add(input);
        return this;
    }


    public TransactionBuilder spendFromOutpoint(TransactionOutpoint outpoint, long sequenceNumber, UnlockingScriptBuilder unlocker) {

        TransactionInput input = new TransactionInput(
                HEX.decode(outpoint.getTransactionId()),
                outpoint.getOutputIndex(),
                sequenceNumber,
                unlocker
        );

        String mapKey = outpoint.getTransactionId() + ":" + outpoint.getOutputIndex();
        spendingMap.put(mapKey, outpoint.getSatoshis());

        inputs.add(input);
        return this;
    }

    public TransactionBuilder spendFromOutput(String utxoTxnId, int outputIndex, BigInteger amount, long sequenceNumber, UnlockingScriptBuilder unlocker) {

        TransactionInput input = new TransactionInput(
                HEX.decode(utxoTxnId),
                outputIndex,
                sequenceNumber,
                unlocker
        );

        String mapKey = utxoTxnId + ":" + outputIndex;
        spendingMap.put(mapKey, amount);

        inputs.add(input);
        return this;
    }


    public TransactionBuilder spendFromOutput(TransactionSigner signer, String utxoTxnId, int outputIndex, BigInteger amount, long sequenceNumber, UnlockingScriptBuilder unlocker) {

        TransactionOutpoint outpoint = new TransactionOutpoint();
        outpoint.setOutputIndex(outputIndex);
        outpoint.setLockingScript(unlocker.getUnlockingScript());
        outpoint.setSatoshis(amount);
        outpoint.setTransactionId(utxoTxnId);

        String mapKey = utxoTxnId + ":" + outputIndex;
        this.signerMap.put(mapKey, new SignerDto(signer, outpoint));

        TransactionInput input = new TransactionInput(
                HEX.decode(utxoTxnId),
                outputIndex,
                sequenceNumber,
                unlocker
        );

        spendingMap.put(mapKey, amount);

        inputs.add(input);
        return this;
    }

    public TransactionBuilder spendTo(LockingScriptBuilder locker, BigInteger satoshis) throws TransactionException{

        int satoshiCompare = satoshis.compareTo(BigInteger.ZERO);
        if (satoshiCompare == -1 ) //equivalent of satoshis < 0
            throw new TransactionException("You can only spend zero or more satoshis in an output");

        Script script;
        if (locker == null) {
            throw new TransactionException("LockingScriptBuilder cannot be null");
        }else{
           script = locker.getLockingScript();
        }

        TransactionOutput txnOutput = new TransactionOutput(satoshis, script);
        outputs.add(txnOutput);

        return this;
    }

    /**
     * Bitcoin Address Where to send any change (lefover satoshis after fees) to
     * @param changeAddress - Bitcoin Address. Implicitly creates a P2PKH output.
     * @return TransactionBuilder
     */
    public TransactionBuilder sendChangeTo(Address changeAddress){
        changeScriptBuilder = new P2PKHLockBuilder(changeAddress);

        return sendChangeTo(changeScriptBuilder);
    }

    /**
     * A flexible way of dictating how to lock up any change output.
     *
     * @param locker - a LockingScriptBuilder instance
     * @return TransactionBuilder
     */
    public TransactionBuilder sendChangeTo(LockingScriptBuilder locker){

        changeScriptBuilder = locker;

        updateChangeOutput();

        changeScriptFlag = true;

        return this;
    }

    public TransactionBuilder withFeePerKb(long fee){
        feePerKb = fee;

        if (changeScriptBuilder != null)
            updateChangeOutput();

        return this;
    }
    /*

    /// Set the locktime flag on the transaction to prevent it becoming
    /// spendable before specified date
    ///
    /// [future] - The date in future before which transaction will not be spendable.
    TransactionBuilder lockUntilDate(DateTime future) {
        if (future.millisecondsSinceEpoch < NLOCKTIME_BLOCKHEIGHT_LIMIT) {
            throw LockTimeException('Block time is set too early');
        }

        for (var input in _txnInputs) {
            if (input.sequenceNumber == DEFAULT_SEQNUMBER) {
                input.sequenceNumber = DEFAULT_LOCKTIME_SEQNUMBER;
            }
        }

        _nLockTime = future.millisecondsSinceEpoch;

        return this;
    }

    /// Set the locktime flag on the transaction to prevent it becoming
    /// spendable before specified date
    ///
    /// [timestamp] - The date in future before which transaction will not be spendable.
    TransactionBuilder lockUntilUnixTime(int timestamp) {
        if (timestamp < NLOCKTIME_BLOCKHEIGHT_LIMIT) {
            throw LockTimeException('Block time is set too early');
        }

        _nLockTime = timestamp;

        return this;
    }

    /// Set the locktime flag on the transaction to prevent it becoming
    /// spendable before specified block height
    ///
    /// [blockHeight] - The block height before which transaction will not be spendable.
    TransactionBuilder lockUntilBlockHeight(int blockHeight) {
        if (blockHeight > Transaction.NLOCKTIME_BLOCKHEIGHT_LIMIT) {
            throw LockTimeException('Block height must be less than 500000000');
        }

        if (blockHeight < 0) {
            throw LockTimeException("Block height can't be negative");
        }


        for (var input in _txnInputs) {
            if (input.sequenceNumber == Transaction.DEFAULT_SEQNUMBER) {
                input.sequenceNumber = Transaction.DEFAULT_LOCKTIME_SEQNUMBER;
            }
        }

        //FIXME: assumption on the length of _nLockTime. Risks indexexception
        _nLockTime = blockHeight;

        return this;
    }
     */


    public Transaction build(boolean performChecks) throws TransactionException, IOException, SigHashException, SignatureDecodeException {
        if (performChecks){
            runTransactionChecks();
        }

        Transaction tx = new Transaction();

        //add transaction inputs
        tx.addInputs(inputs);

        if (changeScriptBuilder != null) {
            tx.addOutput(getChangeOutput());
        }

        //add transaction outputs
        tx.addOutputs(outputs);


        tx.setLockTime(nLockTime);

        //update inputs with signatures
//        String txId = tx.getTransactionId();
        for (int index = 0; index < inputs.size() ; index++) {
            TransactionInput currentInput = inputs.get(index);

            List<Map.Entry<String, SignerDto>> result = signerMap.entrySet().stream().filter( (Map.Entry<String, SignerDto> entry) -> {
                String entryKey = entry.getValue().outpoint.getTransactionId() + ":" + entry.getValue().outpoint.getOutputIndex();
                String currentInputKey = Utils.HEX.encode(currentInput.getPrevTxnId()) + ":" + currentInput.getPrevTxnOutputIndex();
                return entryKey.equals(currentInputKey);
            }).collect(Collectors.toList());

            if (result.size() > 0) {

                SignerDto dto = result.get(0).getValue();
                TransactionOutput utxoToSpend = new TransactionOutput(dto.outpoint.getSatoshis(), dto.outpoint.getLockingScript());

                //TODO: this side-effect programming where the signer mutates my local variable
                //      still bothers me.
                dto.signer.sign(tx, utxoToSpend, index);
            }
        }

        return tx;

    }

    private void runTransactionChecks() throws TransactionException {
        if (invalidSatoshis()) {
            throw new TransactionException("Invalid quantity of satoshis");
        }

        BigInteger unspent = getUnspentValue();
        if (unspent.compareTo(BigInteger.ZERO) == -1) {
            if (!transactionOptions.contains(TransactionOption.DISABLE_MORE_OUTPUT_THAN_INPUT)) {
                throw new TransactionException("Invalid output sum of satoshis");
            }
        } else {
            checkForFeeErrors(unspent);
        }

        checkForDustErrors();
        //TODO: This might be a useful check, but can't be done in Builder
        //checkForMissingSignatures();

    }

//    private void checkForMissingSignatures(){
//        if (transactionOptions.contains(TransactionOption.DISABLE_FULLY_SIGNED)) return;
//
//        if (!isFullySigned()) {
//            throw new TransactionException("Missing Signatures");
//        }
//    }


    private void checkForDustErrors() throws TransactionException {
        if (transactionOptions.contains(TransactionOption.DISABLE_DUST_OUTPUTS)) {
            return;
        }

        for (TransactionOutput output : outputs) {
            if (output.getAmount().compareTo(DUST_AMOUNT) == -1 ) {
                throw new TransactionException("You have outputs with spending values below the dust limit of " + DUST_AMOUNT.toString());
            }
        }

        //check for dust on change output
        if (getChangeOutput() != null && (getChangeOutput().getAmount().compareTo(DUST_AMOUNT) == -1)){
            throw new TransactionException("You have a change output with spending value below the dust limit of " + DUST_AMOUNT.toString());
        }

    }


    private void checkForFeeErrors(BigInteger unspent) throws TransactionException {
        if ((transactionFee != null) && (transactionFee.compareTo(unspent) != 0)) {
            String errorMessage = "Unspent value is " + unspent.toString(10) + " but specified fee is " + transactionFee.toString(10);
            throw new TransactionException(errorMessage);
        }

        if (!transactionOptions.contains(TransactionOption.DISABLE_LARGE_FEES)) {
            BigInteger maximumFee = FEE_SECURITY_MARGIN.multiply(estimateFee());
            if (unspent.compareTo(maximumFee) == 1) {
                if (!changeScriptFlag) {
                    throw new TransactionException("Fee is too large and no change address was provided");
                }

                throw new TransactionException("expected less than " + maximumFee.toString() + " but got " + unspent.toString());
            }
        }
    }

    private BigInteger getUnspentValue(){

        BigInteger inputAmount = calcInputTotals();
        BigInteger outputAmount = calcRecipientTotals();
        BigInteger unspent = inputAmount.subtract(outputAmount);

        return unspent;
    }

    private boolean invalidSatoshis() {
        for (TransactionOutput output: outputs){
            //    if (this._satoshis > MAX_SAFE_INTEGER) {
            if (output.getAmount().compareTo(BigInteger.ZERO) == -1)
                return true;

            //can't spend more than the total moneysupply of Bitcoin
            if (output.getAmount().compareTo(BigInteger.valueOf(Transaction.MAX_MONEY)) == 1)
                return true;
        }

        return false;
    }


    private void updateChangeOutput(){
        //spent amount equals input amount. No change generated. Return.
        if (calcRecipientTotals() == calcInputTotals()) return;

        //clear change outputs
        changeOutput = null;

        changeAmount = calculateChange();
        TransactionOutput output = getChangeOutput();
        output.setAmount(changeAmount);
    }

    private TransactionOutput getChangeOutput(){

        if (changeScriptBuilder == null) return null;

        if (changeOutput == null ){
            changeOutput = new TransactionOutput(BigInteger.ZERO, changeScriptBuilder.getLockingScript());
        }

        return changeOutput;
    }

    public BigInteger calculateChange(){
        BigInteger inputAmount = calcInputTotals();
        BigInteger outputAmount = calcRecipientTotals();
        BigInteger unspent = inputAmount.subtract(outputAmount);

        return unspent.subtract(getFee()); //sub
    }

    public BigInteger getFee(){

        if (transactionFee != null){
            return transactionFee;
        }

        //if no change output set, fees should equal to all the unspent amount
        if (changeOutput == null){
            return calcInputTotals().subtract(calcRecipientTotals());
        }

        return estimateFee();

    }

    private BigInteger estimateFee(){
        long size = estimateSize();

        BigInteger fee = BigInteger.valueOf(new Float(size / 1000 * feePerKb).longValue());

        //if fee is less that 256, set fee at 256 satoshis
        //this is current minimum we set automatically if no explicit fee given
        //FIXME: Make this configurable
        if (fee.compareTo(BigInteger.valueOf(256)) == -1){
            fee = BigInteger.valueOf(256);
        }

        return fee;
    }

    public long estimateSize(){
        int result = MAXIMUM_EXTRA_SIZE;

        for (TransactionInput input: inputs){
            result += SCRIPT_MAX_SIZE; //TODO: we're only spending P2PKH atm.
        }

        for (TransactionOutput output: outputs) {
            result += output.getScript().getProgram().length + 9;
        }

        return result;
    }

    public BigInteger calcInputTotals(){

        BigInteger amount = BigInteger.ZERO;
        for (BigInteger value : spendingMap.values()) {
            amount = amount.add(value);
        }

        return amount;
    }

    public BigInteger calcRecipientTotals() {

        BigInteger amount = BigInteger.ZERO;
        for (TransactionOutput output: outputs) {
            amount = amount.add(output.getAmount());
        };

        //deduct change output
        if (changeScriptBuilder != null){
            TransactionOutput changeOutput = getChangeOutput();
            amount = amount.add(changeOutput.getAmount());
        }

        return amount;
    }

}
