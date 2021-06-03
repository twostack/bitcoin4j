/*
 * Copyright 2014 Google Inc.
 * Copyright 2016 Andreas Schildbach
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

package org.twostack.bitcoin.transaction;

import org.junit.Test;
import org.twostack.bitcoin.PrivateKey;
import org.twostack.bitcoin.address.Address;
import org.twostack.bitcoin.exception.InvalidKeyException;
import org.twostack.bitcoin.exception.TransactionException;
import org.twostack.bitcoin.params.NetworkAddressType;

import java.io.IOException;
import java.math.BigInteger;

import static org.junit.Assert.assertEquals;

/**
 * Just check the Transaction.verify() method. Most methods that have complicated logic in Transaction are tested
 * elsewhere, e.g. signing and hashing are well exercised by the wallet tests, the full block chain tests and so on.
 * The verify method is also exercised by the full block chain tests, but it can also be used by API users alone,
 * so we make sure to cover it here as well.
 */
public class TransactionTest {

    String tx1hex = "01000000015884e5db9de218238671572340b207ee85b628074e7e467096c267266baf77a4000000006a473044022013fa3089327b50263029265572ae1b022a91d10ac80eb4f32f291c914533670b02200d8a5ed5f62634a7e1a0dc9188a3cc460a986267ae4d58faf50c79105431327501210223078d2942df62c45621d209fab84ea9a7a23346201b7727b9b45a29c4e76f5effffffff0150690f00000000001976a9147821c0a3768aa9d1a37e16cf76002aef5373f1a888ac00000000";
    String tx1id = "779a3e5b3c2c452c85333d8521f804c1a52800e60f4b7c3bbe36f4bab350b72c";
    String txEmptyHex = "01000000000000000000";
    String coinbaseOutput = "02000000016b748661a108dc35d8868a9a552b9364c6ee3f06a4604f722882d49cdc4d13020000000048473044022073062451397fb5e7e2e02f1603e2a92677d516a5e747b1ae2ad0996387916d4302200ae2ec97d4525621cef07f75f0b92b5e83341761fa604c83daf0390a76d5024241feffffff0200e1f505000000001976a91494837d2d5d6106aa97db38957dcc294181ee91e988ac00021024010000001976a9144d991c88b4fd954ea62aa7182d3b3e251896a83188acd5000000";


    @Test
    public void TestSerializeDeserialize() throws IOException {
        Transaction transaction = Transaction.fromHex(tx1hex);
        assertEquals(tx1hex, transaction.uncheckedSerialize());
    }

    @Test
    public void can_create_and_sign_transaction() throws InvalidKeyException, TransactionException {

        PrivateKey privateKey = PrivateKey.fromWIF("cVVvUsNHhbrgd7aW3gnuGo2qJM45LhHhTCVXrDSJDDcNGE6qmyCs");
        Address changeAddress = Address.fromString(NetworkAddressType.TEST_PKH, "mu4DpTaD75nheE4z5CQazqm1ivej1vzL4L"); // my address
        Address recipientAddress = Address.fromString(NetworkAddressType.TEST_PKH, "n3aZKucfWmXeXhX13MREQQnqNfbrWiYKtg"); //bitcoin-cli address

        //Create a Transaction instance from the RAW transaction data create by bitcoin-cli.
        //this transaction contains the UTXO we are interested in
        Transaction txWithUTXO = Transaction.fromHex(coinbaseOutput);

        //Let's create the set of Spending Transaction Inputs. These Transaction Inputs need to refer to the Outputs in
        //the Transaction we are spending from.

        P2PKHLockBuilder locker = new P2PKHLockBuilder(recipientAddress);
        P2PKHUnlockBuilder unlocker = new P2PKHUnlockBuilder(privateKey.getPublicKey());
        Transaction unsignedTxn = new TransactionBuilder()
         .spendFromTransaction(txWithUTXO, 0, Transaction.NLOCKTIME_MAX_VALUE, unlocker) //set global sequenceNumber/nLocktime time for each Input created
         .spendTo(recipientAddress, BigInteger.valueOf(50000000L), locker) //spend half of a bitcoin (we should have 1 in the UTXO)
         .sendChangeTo(changeAddress, locker) // spend change to myself
         .withFeePerKb(100000)
         .build();

         TransactionOutput utxoToSign = txWithUTXO.getOutputs().get(0);
         Transaction signedTx = new TransactionSigner().sign(unsignedTxn, utxoToSign,0, privateKey, SigHashType.ALL.byteValue() | SigHashType.FORKID.byteValue());
//
//        //Sign the Transaction Input
//
//        //FIXME: Where's the assertion ?
//
    }
}
