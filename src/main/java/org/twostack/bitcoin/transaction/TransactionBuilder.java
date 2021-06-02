package org.twostack.bitcoin.transaction;

import org.twostack.bitcoin.address.Address;

import java.math.BigInteger;

public class TransactionBuilder {


    public TransactionBuilder spendFromOutput(TransactionOutput utxo, long nlocktimeMaxValue, P2PKHUnlockBuilder unlocker) {
        return this;
    }

    public TransactionBuilder spendTo(Address recipientAddress, BigInteger satoshis, LockingScriptBuilder locker) {
       return this;
    }


    public TransactionBuilder sendChangeTo(Address changeAddress, LockingScriptBuilder locker){
       return this;
    }

    public TransactionBuilder withFeePerKb(long fee){
        return this;
    }

    public Transaction build(){
        return new Transaction();
    }
}
