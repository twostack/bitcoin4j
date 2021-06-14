package org.twostack.bitcoin4j.transaction;

import org.twostack.bitcoin4j.Address;
import org.twostack.bitcoin4j.exception.TransactionException;
import org.twostack.bitcoin4j.script.Script;

import javax.annotation.Nullable;
import java.math.BigInteger;
import java.util.*;

import static org.twostack.bitcoin4j.Utils.HEX;

public class TransactionBuilder {

    private List<TransactionInput> inputs = new ArrayList<>();
    private List<TransactionOutput> outputs = new ArrayList<>();

    //Map the transactionIds we're spending from, to the corresponding UXTO amount in the output
    private Map<String, BigInteger> spendingMap = new HashMap();

    private LockingScriptBuilder changeScriptBuilder;
    private BigInteger changeAmount = BigInteger.ZERO;
    private TransactionOutput changeOutput;

    private final long DEFAULT_FEE_PER_KB = 512; //amount in satoshis

    static final BigInteger DUST_AMOUNT = BigInteger.valueOf(546);

    /// Margin of error to allow fees in the vecinity of the expected value but doesn't allow a big difference
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

    /*
        utxoMap is expect to have :

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

        spendingMap.put((String) utxoMap.get("transactionId"), (BigInteger) utxoMap.get("satoshis"));

        inputs.add(input);

        return this;

    }

    public TransactionBuilder spendFromTransaction(Transaction txn, int outputIndex, long sequenceNumber, UnlockingScriptBuilder unlocker){

        TransactionInput input = new TransactionInput(
                txn.getTransactionIdBytes(),
                outputIndex,
                sequenceNumber,
                unlocker
        );

        spendingMap.put(txn.getTransactionId(), txn.getOutputs().get(outputIndex).getAmount());

        inputs.add(input);
        return this;

    }

//    public TransactionBuilder spendFromOutput(byte[] utxoTxnId, TransactionOutput utxo, long sequenceNumber, P2PKHUnlockBuilder unlocker) {
//
//        TransactionInput input = new TransactionInput(
//                utxoTxnId,
//                utxo.getOutputIndex(),
//                sequenceNumber,
//                unlocker
//        );
//
//        inputs.add(input);
//        return this;
//    }

    public TransactionBuilder spendTo(LockingScriptBuilder locker, BigInteger satoshis) throws TransactionException{

        int satoshiCompare = satoshis.compareTo(BigInteger.ZERO);
        if (satoshiCompare == -1 ||  satoshiCompare == 0) //equivalent of satoshis <= 0
            throw new TransactionException("You can only spend a positive amount of satoshis");

        Script script;
        if (locker == null) {
            throw new TransactionException("LockingScriptBuilder cannot be null");
        }else{
           script = locker.getScriptPubkey();
        }

        TransactionOutput txnOutput = new TransactionOutput(satoshis, script);
        outputs.add(txnOutput);

        return this;
    }


    public TransactionBuilder sendChangeTo(Address changeAddress, @Nullable LockingScriptBuilder locker){

        if (locker == null) {
            changeScriptBuilder = new P2PKHLockBuilder(changeAddress);
        }else{
            changeScriptBuilder = locker;
        }

        if (changeScriptBuilder != null)
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

    public Transaction build(boolean performChecks) throws TransactionException {
        if (performChecks){
            runTransactionChecks();
        }

        Transaction tx = new Transaction();

        //add transaction inputs
        tx.addInputs(inputs);

        //add transaction outputs
        tx.addOutputs(outputs);

        tx.setLockTime(nLockTime);

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

        changeAmount = calculateChange();
        TransactionOutput output = getChangeOutput();
        output.setAmount(changeAmount);
    }

    private TransactionOutput getChangeOutput(){
        if (changeOutput == null ){
            changeOutput = new TransactionOutput(BigInteger.ZERO, changeScriptBuilder.getScriptPubkey());
        }

        return changeOutput;
    }

    private BigInteger calculateChange(){
        BigInteger inputAmount = calcInputTotals();
        BigInteger outputAmount = calcRecipientTotals();
        BigInteger unspent = inputAmount.subtract(outputAmount);

        return unspent.subtract(getFee()); //sub
    }

    private BigInteger getFee(){

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

        return fee;
    }

    private long estimateSize(){
        int result = MAXIMUM_EXTRA_SIZE;

        for (TransactionInput input: inputs){
            result += SCRIPT_MAX_SIZE; //TODO: we're only spending P2PKH atm.
        }

        for (TransactionOutput output: outputs) {
            result += output.getScript().getProgram().length + 9;
        }

        return result;
    }

    private BigInteger calcInputTotals(){

        BigInteger amount = BigInteger.ZERO;
        for (BigInteger value : spendingMap.values()) {
            amount = amount.add(value);
        }

        return amount;
    }

    private BigInteger calcRecipientTotals() {

        BigInteger amount = BigInteger.ZERO;
        for (TransactionOutput output: outputs) {
            amount = amount.add(output.getAmount());
        };

        return amount;
    }

}
