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

package org.twostack.bitcoin4j.transaction;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.IntNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.google.common.base.Charsets;
import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.twostack.bitcoin4j.*;
import org.twostack.bitcoin4j.Address;
import org.twostack.bitcoin4j.address.LegacyAddress;
import org.twostack.bitcoin4j.exception.*;
import org.twostack.bitcoin4j.params.NetworkType;
import org.twostack.bitcoin4j.script.Interpreter;
import org.twostack.bitcoin4j.script.Script;

import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.junit.Assert.*;
import static org.twostack.bitcoin4j.Utils.HEX;
import static org.twostack.bitcoin4j.utils.TestUtil.parseScriptString;

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

    private static final Logger log = LoggerFactory.getLogger(TransactionTest.class);

    @Test
    public void TestSerializeDeserialize() throws IOException {
        Transaction transaction = Transaction.fromHex(tx1hex);
        assertEquals(tx1hex, HEX.encode(transaction.serialize()));
    }

    @Test
    public void TestTransactionIdMatchesTransactionHash() {
        Transaction transaction = Transaction.fromHex(tx1hex);
        assertEquals(tx1id, transaction.getTransactionId());
    }

    @Test
    public void canCreateAndSignTransactionWithoutChange() throws InvalidKeyException, TransactionException, IOException, SigHashException {

        PrivateKey privateKey = PrivateKey.fromWIF("cVVvUsNHhbrgd7aW3gnuGo2qJM45LhHhTCVXrDSJDDcNGE6qmyCs");
        Address changeAddress = Address.fromString(NetworkType.TEST, "mu4DpTaD75nheE4z5CQazqm1ivej1vzL4L"); // my address
        Address recipientAddress = Address.fromString(NetworkType.TEST, "n3aZKucfWmXeXhX13MREQQnqNfbrWiYKtg"); //bitcoin-cli address

        //Create a Transaction instance from the RAW transaction data create by bitcoin-cli.
        //this transaction contains the UTXO we are interested in
        Transaction txWithUTXO = Transaction.fromHex(coinbaseOutput);

        //Let's create the set of Spending Transaction Inputs. These Transaction Inputs need to refer to the Outputs in
        //the Transaction we are spending from.

        P2PKHLockBuilder locker = new P2PKHLockBuilder(recipientAddress);
        P2PKHUnlockBuilder unlocker = new P2PKHUnlockBuilder(privateKey.getPublicKey());
        Transaction unsignedTxn = new TransactionBuilder()
                .spendFromTransaction(txWithUTXO, 0, Transaction.NLOCKTIME_MAX_VALUE, unlocker) //set global sequenceNumber/nLocktime time for each Input created
                .spendTo(locker, BigInteger.valueOf(99999000L))
                .withFeePerKb(512)
                .build(true);

        TransactionOutput utxoToSign = txWithUTXO.getOutputs().get(0);

        //simply check that we have clean e2e execution
        Assertions.assertThatCode(() -> {
            new TransactionSigner().sign(unsignedTxn, utxoToSign,0, privateKey, SigHashType.ALL.value | SigHashType.FORKID.value);
        }).doesNotThrowAnyException();

        //System.out.println(HEX.encode(signedTx.serialize()));
    }

    @Test
    public void can_create_and_sign_transaction() throws InvalidKeyException, TransactionException, IOException, SigHashException {

        PrivateKey privateKey = PrivateKey.fromWIF("cVVvUsNHhbrgd7aW3gnuGo2qJM45LhHhTCVXrDSJDDcNGE6qmyCs");
        Address changeAddress = Address.fromString(NetworkType.TEST, "mu4DpTaD75nheE4z5CQazqm1ivej1vzL4L"); // my address
        Address recipientAddress = Address.fromString(NetworkType.TEST, "n3aZKucfWmXeXhX13MREQQnqNfbrWiYKtg"); //bitcoin-cli address

        //Create a Transaction instance from the RAW transaction data create by bitcoin-cli.
        //this transaction contains the UTXO we are interested in
        Transaction txWithUTXO = Transaction.fromHex(coinbaseOutput);

        //Let's create the set of Spending Transaction Inputs. These Transaction Inputs need to refer to the Outputs in
        //the Transaction we are spending from.

        P2PKHLockBuilder locker = new P2PKHLockBuilder(recipientAddress);
        P2PKHUnlockBuilder unlocker = new P2PKHUnlockBuilder(privateKey.getPublicKey());
        Transaction unsignedTxn = new TransactionBuilder()
         .spendFromTransaction(txWithUTXO, 0, Transaction.NLOCKTIME_MAX_VALUE, unlocker) //set global sequenceNumber/nLocktime time for each Input created
         .spendTo(locker, BigInteger.valueOf(50000000L)) //spend half of a bitcoin (we should have 1 in the UTXO)
         .sendChangeTo(changeAddress, locker) // spend change to myself
         .withFeePerKb(100000)
         .build(false);

         TransactionOutput utxoToSign = txWithUTXO.getOutputs().get(0);

         //simply check that we have clean e2e execution
         Assertions.assertThatCode(() -> {
             new TransactionSigner().sign(unsignedTxn, utxoToSign,0, privateKey, SigHashType.ALL.value | SigHashType.FORKID.value);
         }).doesNotThrowAnyException();

        //System.out.println(HEX.encode(signedTx.serialize()));
    }

    @Test
    public void test_transaction_serialization_vectors() throws IOException, TransactionException, InvalidKeyException, SigHashException, SignatureDecodeException {

        JsonNode json = new ObjectMapper().readTree(
                new InputStreamReader(getClass().getResourceAsStream("tx_creation.json"),
                StandardCharsets.UTF_8)
        );

        for (JsonNode test : json) {
//            if (test.isArray() && test.size() == 1 && test.get(0).isTextual())
//                continue; // This is a comment.
            Transaction transaction = null;

            ArrayNode fromNode = (ArrayNode) test.get("from");
            ArrayNode toNodes = (ArrayNode) test.get("to");
            ArrayNode privateKeyNode = (ArrayNode) test.get("sign");
            TextNode  serializedTxNode = (TextNode) test.get("serialize");

            //get utxo deets
            ObjectNode fromObj = (ObjectNode) fromNode.get(0).get(0);
            String address = ((TextNode)fromObj.get("address")).textValue();
            String txId = ((TextNode)fromObj.get("txId")).textValue();
            int outputIndex = ((IntNode)fromObj.get("outputIndex")).asInt();
            String scriptPubKeyText = ((TextNode)fromObj.get("scriptPubKey")).textValue();
            Script scriptPubKey = Script.fromByteArray(HEX.decode(scriptPubKeyText));
            int satoshis = ((IntNode)fromObj.get("satoshis")).asInt();

            Map<String, Object> utxoMap = new HashMap<>();
            utxoMap.put("transactionId", txId);
            utxoMap.put("satoshis", BigInteger.valueOf(satoshis));
            utxoMap.put("sequenceNumber", TransactionInput.MAX_SEQ_NUMBER);
            utxoMap.put("outputIndex", outputIndex);
            utxoMap.put("scriptPubKey", scriptPubKeyText);

            //Build the Transaction
            TransactionBuilder builder = new TransactionBuilder();

            //get txout
            //FIXME: iterate over all outputs
//            ObjectNode txOutNode = (ObjectNode) toNode.get(0);
            for (JsonNode txOutNode: toNodes){
                String toAddress = txOutNode.get(0).textValue();
                int spendAmount = txOutNode.get(1).asInt();

                builder.spendTo(new P2PKHLockBuilder(LegacyAddress.fromString(NetworkType.TEST, toAddress)) , BigInteger.valueOf(spendAmount));
            }

            //signature
            String privateKeyWiF = privateKeyNode.get(0).asText();
            PrivateKey privateKey = PrivateKey.fromWIF(privateKeyWiF);
            int sighashType = privateKeyNode.get(1).asInt();

            //txHex
            String serializedTx = serializedTxNode.asText();

            System.out.println(txId);

            builder.spendFromUtxoMap(utxoMap, new P2PKHUnlockBuilder(privateKey.getPublicKey()));
            builder.withFeePerKb(100000);

            Transaction tx = builder.build(false);

            TransactionSigner signer = new TransactionSigner();
            signer.sign(
                    tx,
                    new TransactionOutput(BigInteger.valueOf(satoshis), scriptPubKey),
                    0,
                    privateKey,
                    sighashType);

            assertEquals(serializedTx, HEX.encode(tx.serialize()));


        }

    }


    /*
    Tests that the provided test vectors provide valid spending transactions for the corresponding UTXOs
     */
    @Test
    public void dataDrivenValidTransactions() throws Exception {
        JsonNode json = new ObjectMapper().readTree(new InputStreamReader(getClass().getResourceAsStream("tx_valid.json"), StandardCharsets.UTF_8));
        for (JsonNode test : json) {
            if (test.isArray() && test.size() == 1 && test.get(0).isTextual())
                continue; // This is a comment.
            Transaction spendingTx = null;

            try {
                Map<String, Script> scriptPubKeys = parseScriptPubKeys(test.get(0));
                spendingTx = Transaction.fromHex(test.get(1).asText().toLowerCase());
                spendingTx.verify();
                Set<Script.VerifyFlag> verifyFlags = parseVerifyFlags(test.get(2).asText());

                for (int i = 0; i < spendingTx.getInputs().size(); i++) {
                    TransactionInput input = spendingTx.getInputs().get(i);
                    if (input.getPrevTxnOutputIndex() == 0xffffffffL) {
                        input.setPrevTxnOutputIndex(-1);
                    }

                    //reconstruct the key into our Map of Public Keys using the details from
                    //the parsed transaction
                    String txId = HEX.encode(input.getPrevTxnId());
                    String keyName = "" + input.getPrevTxnOutputIndex() + ":" + txId;

                    //assert that our parsed transaction has correctly extracted the provided
                    //UTXO details
                    assertTrue(scriptPubKeys.containsKey(keyName));
                    Interpreter interp = new Interpreter();
                    interp.correctlySpends( input.getScriptSig(), scriptPubKeys.get(keyName), spendingTx, i , verifyFlags);

                    System.out.println(test.get(0));
                    //TODO: Would be better to assert expectation that no exception is thrown ?
                }
            } catch (Exception e) {
                System.err.println(test);
                if (spendingTx!= null)
                    System.err.println(spendingTx);
                throw e;
            }
        }
    }


    @Test
    public void dataDrivenInvalidTransactions() throws Exception {
        JsonNode json = new ObjectMapper().readTree(new InputStreamReader(getClass().getResourceAsStream(
                "tx_invalid.json"), Charsets.UTF_8));
        for (JsonNode test : json) {
            if (test.isArray() && test.size() == 1 && test.get(0).isTextual())
                continue;

            Transaction spendingTx = null;

            Map<String, Script> scriptPubKeys = parseScriptPubKeys(test.get(0));
            spendingTx = Transaction.fromHex(test.get(1).asText().toLowerCase());
            Set<Script.VerifyFlag> verifyFlags = parseVerifyFlags(test.get(2).asText());

            boolean valid = true;
            try {
                spendingTx.verify();
            } catch (VerificationException e) {
                valid = false;
            }

            // Bitcoin Core checks this case in CheckTransaction, but we leave it to
            // later where we will see an attempt to double-spend, so we explicitly check here
//            for (TransactionInput input : spendingTx.getInputs()) {
//                if (set.contains(input.getOutpoint()))
//                    valid = false;
//                set.add(input.getOutpoint());
//            }

            for (int i = 0; i < spendingTx.getInputs().size() && valid; i++) {
                TransactionInput input = spendingTx.getInputs().get(i);

                //reconstruct the key into our Map of Public Keys using the details from
                //the parsed transaction
                String txId = HEX.encode(input.getPrevTxnId());
                String keyName = "" + input.getPrevTxnOutputIndex() + ":" + txId;

                assertTrue(scriptPubKeys.containsKey(keyName));
                try {
                    Interpreter interp = new Interpreter();
                    interp.correctlySpends( input.getScriptSig(), scriptPubKeys.get(keyName), spendingTx, i , verifyFlags);

                } catch (VerificationException e) {
                    valid = false;
                }

            }
            System.out.println(test.get(0));

            if (valid)
                fail();
        }
    }


    private Set<Script.VerifyFlag> parseVerifyFlags(String str) {
        Set<Script.VerifyFlag> flags = EnumSet.noneOf(Script.VerifyFlag.class);
        if (!"NONE".equals(str)) {
            for (String flag : str.split(",")) {
                try {
                    flags.add(Script.VerifyFlag.valueOf(flag));
                } catch (IllegalArgumentException x) {
                    log.debug("Cannot handle verify flag {} -- ignored.", flag);
                }
            }
        }
        return flags;
    }

    private Map<String, Script> parseScriptPubKeys(JsonNode inputs) throws IOException {
        Map<String, Script> scriptPubKeys = new HashMap<String, Script>();
        for (JsonNode input : inputs) {
            String hash = input.get(0).asText();
            int index = input.get(1).asInt();
            String script = input.get(2).asText();
            Sha256Hash sha256Hash = Sha256Hash.wrap(HEX.decode(hash));
            scriptPubKeys.put("" + index + ":" + sha256Hash.toString(), parseScriptString(script));
        }
        return scriptPubKeys;
    }

}
