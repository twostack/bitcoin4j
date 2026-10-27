
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
import org.twostack.bitcoin4j.VarInt;
import org.twostack.bitcoin4j.exception.SigHashException;
import org.twostack.bitcoin4j.exception.SignatureDecodeException;
import org.twostack.bitcoin4j.exception.TransactionException;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptChunk;
import org.twostack.bitcoin4j.script.ScriptOpCodes;
import org.twostack.bitcoin4j.script.ScriptPattern;

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

    /// Sequence number given to final inputs when a lock time is set, so the lock time is enforced
    static final long DEFAULT_LOCKTIME_SEQNUMBER = TransactionInput.MAX_SEQ_NUMBER - 1;

    /// Transaction version to build with. null means the Transaction default.
    private Long txVersion = null;

    //Map the outpoints we're spending from ("transactionId:outputIndex"), to their locking script, where known.
    //Used to estimate the size of the unlocking script for fee calculation.
    private Map<String, Script> lockingScriptMap = new HashMap<>();

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
    /// scriptPubKey in a utxo map may be given as hex (preferred) or as ASM
    private static Script parseScriptPubKey(String scriptPubKey) {
        if (scriptPubKey.length() % 2 == 0 && scriptPubKey.matches("[0-9a-fA-F]*")) {
            return new Script(HEX.decode(scriptPubKey));
        }
        return Script.fromAsmString(scriptPubKey);
    }

    public TransactionBuilder spendFromUtxoMap(TransactionSigner signer, Map<String, Object> utxoMap, @Nullable  UnlockingScriptBuilder unlocker){

        String transactionId = (String) utxoMap.get("transactionId");

        int outputIndex = (int ) utxoMap.get("outputIndex");
        long sequenceNumber = (long) utxoMap.get("sequenceNumber");

        TransactionOutpoint outpoint = new TransactionOutpoint();
        outpoint.setOutputIndex(outputIndex);
        outpoint.setLockingScript(parseScriptPubKey((String)utxoMap.get("scriptPubKey")));
        outpoint.setSatoshis((BigInteger)utxoMap.get("satoshis"));
        outpoint.setTransactionId(transactionId);

        String mapKey = transactionId + ":" + outputIndex;

        this.signerMap.put(mapKey, new SignerDto(signer, outpoint));
        lockingScriptMap.put(mapKey, outpoint.getLockingScript());

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
        lockingScriptMap.put(mapKey, output.getScript());

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
        lockingScriptMap.put(mapKey, txn.getOutputs().get(outputIndex).getScript());

        inputs.add(input);
        return this;

    }

    public TransactionBuilder spendFromOutpoint(TransactionSigner signer, TransactionOutpoint outpoint, long sequenceNumber, UnlockingScriptBuilder unlocker) {

        String mapKey = outpoint.getTransactionId() + ":" + outpoint.getOutputIndex();
        this.signerMap.put(mapKey, new SignerDto(signer, outpoint));
        if (outpoint.getLockingScript() != null) {
            lockingScriptMap.put(mapKey, outpoint.getLockingScript());
        }

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
        if (outpoint.getLockingScript() != null) {
            lockingScriptMap.put(mapKey, outpoint.getLockingScript());
        }

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


    /**
     * @deprecated A signer has to sign over the spent Output's locking script, which this overload
     * does not receive. Use {@link #spendFromOutput(TransactionSigner, String, int, BigInteger, Script, long, UnlockingScriptBuilder)}.
     * @throws IllegalArgumentException always
     */
    @Deprecated
    public TransactionBuilder spendFromOutput(TransactionSigner signer, String utxoTxnId, int outputIndex, BigInteger amount, long sequenceNumber, UnlockingScriptBuilder unlocker) {
        throw new IllegalArgumentException("Signing requires the locking script of the output being spent. " +
                "Use spendFromOutput(signer, utxoTxnId, outputIndex, amount, lockingScript, sequenceNumber, unlocker)");
    }

    /**
     * Spend from an output, and have the signer sign the corresponding input when the transaction is built.
     *
     * @param lockingScript the locking script (scriptPubKey) of the output being spent. The signature commits to it.
     */
    public TransactionBuilder spendFromOutput(TransactionSigner signer, String utxoTxnId, int outputIndex, BigInteger amount, Script lockingScript, long sequenceNumber, UnlockingScriptBuilder unlocker) {

        TransactionOutpoint outpoint = new TransactionOutpoint();
        outpoint.setOutputIndex(outputIndex);
        outpoint.setLockingScript(lockingScript);
        outpoint.setSatoshis(amount);
        outpoint.setTransactionId(utxoTxnId);
        lockingScriptMap.put(utxoTxnId + ":" + outputIndex, lockingScript);

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

        //the change amount is calculated when the transaction is built, so that
        //outputs, inputs and fee settings added after this call are accounted for
        changeScriptBuilder = locker;

        changeScriptFlag = true;

        return this;
    }

    public TransactionBuilder withFeePerKb(long fee){
        feePerKb = fee;

        return this;
    }

    /**
     * Set the version number of the transaction that will be built. Defaults to the Transaction default (2).
     */
    public TransactionBuilder withTxVersion(long version){
        txVersion = version;
        return this;
    }

    /**
     * Relax one of the checks performed by {@link #build(boolean)}.
     */
    public TransactionBuilder withOption(TransactionOption option){
        if (option == TransactionOption.DISABLE_ALL) {
            transactionOptions.addAll(EnumSet.allOf(TransactionOption.class));
        } else {
            transactionOptions.add(option);
        }
        return this;
    }
    /**
     * Set the locktime flag on the transaction to prevent it becoming
     * spendable before the specified block height.
     *
     * @param blockHeight the block height before which the transaction will not be spendable
     *                    (must be non-negative and less than 500000000)
     * @return this builder for chaining
     */
    public TransactionBuilder lockUntilBlockHeight(int blockHeight) {
        if (blockHeight >= Transaction.LOCKTIME_THRESHOLD) {
            throw new IllegalArgumentException("Block height must be less than " + Transaction.LOCKTIME_THRESHOLD);
        }
        if (blockHeight < 0) {
            throw new IllegalArgumentException("Block height can't be negative");
        }

        nLockTime = blockHeight;
        return this;
    }

    /**
     * Set the locktime flag on the transaction to prevent it becoming
     * spendable before the specified time.
     *
     * @param timestamp Unix time in seconds (must be at least 500000000)
     * @return this builder for chaining
     */
    public TransactionBuilder lockUntilUnixTime(long timestamp) {
        if (timestamp < Transaction.LOCKTIME_THRESHOLD) {
            throw new IllegalArgumentException("Timestamp must be at least " + Transaction.LOCKTIME_THRESHOLD + " (block heights use lockUntilBlockHeight)");
        }
        if (timestamp > Transaction.NLOCKTIME_MAX_VALUE) {
            throw new IllegalArgumentException("Timestamp must be at most " + Transaction.NLOCKTIME_MAX_VALUE);
        }

        nLockTime = timestamp;
        return this;
    }


    public Transaction build(boolean performChecks) throws TransactionException, IOException, SigHashException, SignatureDecodeException {
        updateChangeOutput();

        if (performChecks){
            runTransactionChecks();
        }

        //a lock time is ignored if every input is final, so take the inputs out of final state
        if (nLockTime != 0) {
            for (TransactionInput input : inputs) {
                if (input.getSequenceNumber() == TransactionInput.MAX_SEQ_NUMBER) {
                    input.setSequenceNumber(DEFAULT_LOCKTIME_SEQNUMBER);
                }
            }
        }

        Transaction tx = new Transaction();
        if (txVersion != null) {
            tx.setVersion(txVersion);
        }

        //add transaction inputs
        tx.addInputs(inputs);

        //add transaction outputs
        tx.addOutputs(outputs);

        //change output always goes last
        if (changeOutput != null) {
            tx.addOutput(changeOutput);
        }

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
            //unspendable data outputs (OP_RETURN / OP_FALSE OP_RETURN) usually carry 0 satoshis
            if (isDataOutput(output.getScript())) {
                continue;
            }

            if (output.getAmount().compareTo(DUST_AMOUNT) == -1 ) {
                throw new TransactionException("You have outputs with spending values below the dust limit of " + DUST_AMOUNT.toString());
            }
        }

        //check for dust on change output
        if (changeOutput != null && (changeOutput.getAmount().compareTo(DUST_AMOUNT) == -1)){
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

    private static boolean isDataOutput(Script script) {
        if (ScriptPattern.isOpReturn(script)) {
            return true;
        }

        List<ScriptChunk> chunks = script.getChunks();
        return chunks.size() > 1
                && chunks.get(0).equalsOpCode(ScriptOpCodes.OP_FALSE)
                && chunks.get(1).equalsOpCode(ScriptOpCodes.OP_RETURN);
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
        changeOutput = null;
        changeAmount = BigInteger.ZERO;

        if (changeScriptBuilder == null) return;

        //spent amount equals (or exceeds) input amount. No change generated.
        BigInteger unspent = calcInputTotals().subtract(calcSpendTotals());
        if (unspent.signum() <= 0) return;

        //the change output has to exist before estimating the fee, so that its size is accounted for
        changeOutput = new TransactionOutput(BigInteger.ZERO, changeScriptBuilder.getLockingScript());
        BigInteger change = unspent.subtract(getFee());

        if (change.signum() <= 0) {
            //nothing left over after fees
            changeOutput = null;
            return;
        }

        changeAmount = change;
        changeOutput.setAmount(change);
    }

    /**
     * @return the change amount the built transaction will carry (zero if there is no change output)
     */
    public BigInteger calculateChange(){
        updateChangeOutput();
        return changeAmount;
    }

    public TransactionBuilder setFee(BigInteger fee){
        transactionFee = fee;
        return this;
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

        //round up to the next whole satoshi
        BigInteger fee = BigInteger.valueOf(size).multiply(BigInteger.valueOf(feePerKb))
                .add(BigInteger.valueOf(999)).divide(BigInteger.valueOf(1000));

        //if fee is less that 256, set fee at 256 satoshis
        //this is current minimum we set automatically if no explicit fee given
        //FIXME: Make this configurable
        if (fee.compareTo(BigInteger.valueOf(256)) == -1){
            fee = BigInteger.valueOf(256);
        }

        return fee;
    }

    public long estimateSize(){
        long result = MAXIMUM_EXTRA_SIZE;

        for (TransactionInput input: inputs){
            result += estimateInputSize(input);
        }

        for (TransactionOutput output: outputs) {
            result += output.getScript().getProgram().length + 9;
        }

        if (changeOutput != null) {
            result += changeOutput.getScript().getProgram().length + 9;
        }

        return result;
    }

    /// Estimated size of a P2PKH input, including its unlocking script
    private static final int P2PKH_INPUT_SIZE = SCRIPT_MAX_SIZE;
    /// Outpoint (32 + 4) + sequence number (4)
    private static final int INPUT_OVERHEAD = 32 + 4 + 4;
    /// DER signature (up to 72 bytes) + sighash byte + push opcode
    private static final int SIGNATURE_PUSH_SIZE = 72 + 1 + 1;

    private long estimateInputSize(TransactionInput input) {
        Script unlockingScript = input.getUnlockingScriptBuilder() != null
                ? input.getUnlockingScriptBuilder().getUnlockingScript()
                : input.getScriptSig();
        long actualSize = unlockingScript == null ? 0 : unlockingScript.getProgram().length;

        String mapKey = Utils.HEX.encode(input.getPrevTxnId()) + ":" + input.getPrevTxnOutputIndex();
        Script lockingScript = lockingScriptMap.get(mapKey);

        long estimatedSize;
        if (lockingScript != null && ScriptPattern.isP2PK(lockingScript)) {
            estimatedSize = SIGNATURE_PUSH_SIZE;
        } else if (lockingScript != null && ScriptPattern.isSentToMultisig(lockingScript)) {
            //OP_0 followed by m signatures
            int requiredSigs = Script.decodeFromOpN(lockingScript.getChunks().get(0).opcode);
            estimatedSize = 1 + (long) requiredSigs * SIGNATURE_PUSH_SIZE;
        } else if (actualSize > 0) {
            //unknown template, but a script was provided up front (or already signed)
            estimatedSize = actualSize;
        } else {
            return P2PKH_INPUT_SIZE;
        }

        //an unsigned input may hold a partial script, so never estimate below what is already there
        long scriptSize = Math.max(actualSize, estimatedSize);
        return INPUT_OVERHEAD + new VarInt(scriptSize).getSizeInBytes() + scriptSize;
    }

    public BigInteger calcInputTotals(){

        BigInteger amount = BigInteger.ZERO;
        for (BigInteger value : spendingMap.values()) {
            amount = amount.add(value);
        }

        return amount;
    }

    /**
     * @return the total of all outputs, including the change output once it has been calculated
     */
    public BigInteger calcRecipientTotals() {

        BigInteger amount = calcSpendTotals();

        if (changeOutput != null){
            amount = amount.add(changeOutput.getAmount());
        }

        return amount;
    }

    private BigInteger calcSpendTotals() {
        BigInteger amount = BigInteger.ZERO;
        for (TransactionOutput output: outputs) {
            amount = amount.add(output.getAmount());
        }

        return amount;
    }

}
