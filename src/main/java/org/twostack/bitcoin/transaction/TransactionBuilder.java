package org.twostack.bitcoin.transaction;

import org.twostack.bitcoin.address.Address;
import org.twostack.bitcoin.exception.TransactionException;
import org.twostack.bitcoin.script.Script;

import javax.annotation.Nullable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TransactionBuilder {

    private List<TransactionInput> inputs = new ArrayList<>();
    private List<TransactionOutput> outputs = new ArrayList<>();

    //Map the transactionIds we're spending from, to the corresponding UXTO amount in the output
    private Map<String, BigInteger> spendingMap = new HashMap();

    private LockingScriptBuilder changeScriptBuilder;
    private BigInteger changeAmount = BigInteger.ZERO;
    private TransactionOutput changeOutput;

    private final long DEFAULT_FEE_PER_KB = 512; //amount in satoshis

    private long feePerKb = DEFAULT_FEE_PER_KB;

    private BigInteger transactionFee;


    /// Safe upper bound for change address script size in bytes
    static final int CHANGE_OUTPUT_MAX_SIZE = 20 + 4 + 34 + 4;
    static final int MAXIMUM_EXTRA_SIZE = 4 + 9 + 9 + 4;
    static final int SCRIPT_MAX_SIZE = 149;


    public TransactionBuilder spendFromTransaction(Transaction txn, int outputIndex, long sequenceNumber, P2PKHUnlockBuilder unlocker){

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

    public TransactionBuilder spendTo(Address recipientAddress, BigInteger satoshis, @Nullable LockingScriptBuilder locker) throws TransactionException{

        int satoshiCompare = satoshis.compareTo(BigInteger.ZERO);
        if (satoshiCompare == -1 ||  satoshiCompare == 0) //equivalent of satoshis <= 0
            throw new TransactionException("You can only spend a positive amount of satoshis");

        Script script;
        if (locker == null) {
            script = new P2PKHLockBuilder(recipientAddress).getScriptPubkey();
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

        updateChangeOutput();

        return this;
    }

    public TransactionBuilder withFeePerKb(long fee){
        feePerKb = fee;
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

    public Transaction build(){
        return new Transaction();
    }

    private void updateChangeOutput(){
        //spent amount equals input amount. No change generated. Return.
        if (calcRecipientTotals() == calcInputTotals()) return;

        changeAmount = calculateChange();
        TransactionOutput output = getChangeOutput();
        output.setAmount(changeAmount);
    }

    private TransactionOutput getChangeOutput(){
        if (changeOutput == null){
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
        spendingMap.forEach((key, value) -> {
            amount.add(value);
        });

        return amount;
    }

    private BigInteger calcRecipientTotals() {

        BigInteger amount = BigInteger.ZERO;
        for (TransactionOutput output: outputs) {
            amount.add(output.getAmount());
        };

        return amount;
    }
}
