package org.twostack.bitcoin4j.transaction;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.twostack.bitcoin4j.Address;
import org.twostack.bitcoin4j.Coin;
import org.twostack.bitcoin4j.PrivateKey;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.crypto.*;
import org.twostack.bitcoin4j.exception.*;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.bitcoin4j.params.NetworkType;
import org.twostack.bitcoin4j.script.Interpreter;
import org.twostack.bitcoin4j.script.Script;

import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.twostack.bitcoin4j.Utils.WHITESPACE_SPLITTER;

public class TransactionBuilderTest {

    @Test
    public void processAndSignMultiInput() throws IOException, InvalidKeyException, SignatureDecodeException, TransactionException, SigHashException {

        //This WIF is for a private key that actually has testnet coins on TESTNET
        //The transactions in multi_input.json are UTXOs that exist(ed) on TESTNET
        // at time of writing this test, and can be viewed on TESTNET using a block explorer
        String wif = "cRTUuWgPdp7tJPrn1Xeq196eZa4ZCpg8n3cgDJsJmgDHBZ8x9fpv";
        PrivateKey privateKey = PrivateKey.fromWIF(wif);

        JsonNode json = new ObjectMapper().readTree(
                new InputStreamReader(getClass().getResourceAsStream("multi_input.json"),
                        StandardCharsets.UTF_8)
        );

        //build one large transaction that spends all the inputs
        TransactionBuilder builder = new TransactionBuilder();
        for (JsonNode utxoInfo : json) {

            Integer fundingOutputIndex = utxoInfo.get("tx_pos").asInt();
            String rawTxHex = utxoInfo.get("raw_tx").asText();

            Transaction fundingTx = Transaction.fromHex(rawTxHex);

            UnlockingScriptBuilder unlocker = new P2PKHUnlockBuilder(privateKey.getPublicKey());

            TransactionSigner signer = new TransactionSigner(SigHashType.ALL.value | SigHashType.FORKID.value, privateKey);
            builder.spendFromTransaction(signer, fundingTx, fundingOutputIndex, TransactionInput.MAX_SEQ_NUMBER, unlocker);

        }

        Address recipientAddress = Address.fromKey(NetworkAddressType.TEST_PKH, privateKey.getPublicKey());


        Assertions.assertThatCode(() -> {
            Transaction broadcastTx = builder.withFeePerKb(1024)
                    .spendTo(new P2PKHLockBuilder(recipientAddress), BigInteger.valueOf(100000))
                    .sendChangeTo(recipientAddress)
                    .build(true);

            //new Script Interpreter to help us verify our spending conditions
            Interpreter interp = new Interpreter();

            //loop over every one of our spending inputs and verify we are
            //correctly spending those outputs
            for (int scriptSigIndex = 0; scriptSigIndex < 0; scriptSigIndex++) {
                TransactionInput spendingInputOne = TransactionInput.fromByteArray(broadcastTx.getInputs().get(0).serialize());
                String fundingTxId = Utils.HEX.encode(spendingInputOne.getPrevTxnId());
                Integer fundingOutputIndex = json.get(scriptSigIndex).get("tx_pos").asInt();
                Long fundingValue = json.get(scriptSigIndex).get("value").asLong();

                //lookup funding transaction corresponding to first output
                String rawFundingTx = json.get(scriptSigIndex).get("raw_tx").asText();
                Transaction fundingTxOne = Transaction.fromHex(rawFundingTx);
                TransactionOutput fundingOutput = fundingTxOne.getOutputs().get(fundingOutputIndex);

                TransactionSigner signer = new TransactionSigner(SigHashType.FORKID.value | SigHashType.ALL.value, privateKey);
                Transaction signedTx = signer.sign(broadcastTx, fundingOutput, scriptSigIndex);

                //assert that funding transaction is spending correctly
                Set<Script.VerifyFlag> verifyFlags = new HashSet<Script.VerifyFlag>(Arrays.asList(Script.VerifyFlag.SIGHASH_FORKID));
                interp.correctlySpends(signedTx.getInputs().get(scriptSigIndex).getScriptSig(), fundingOutput.getScript(), broadcastTx, scriptSigIndex, verifyFlags, Coin.valueOf(fundingValue));
            }

        }).doesNotThrowAnyException();

    }

    @Test
    public void builderCanSpendFromOutput() throws InvalidKeyException, IOException {

        //This WIF is for a private key that actually has testnet coins on TESTNET
        //The transactions in multi_input.json are UTXOs that exist(ed) on TESTNET
        // at time of writing this test, and can be viewed on TESTNET using a block explorer
        String wif = "cRTUuWgPdp7tJPrn1Xeq196eZa4ZCpg8n3cgDJsJmgDHBZ8x9fpv";
        PrivateKey privateKey = PrivateKey.fromWIF(wif);

        JsonNode json = new ObjectMapper().readTree(
                new InputStreamReader(getClass().getResourceAsStream("multi_input.json"),
                        StandardCharsets.UTF_8)
        );

        //build one large transaction that spends all the inputs
        TransactionBuilder builder = new TransactionBuilder();
        for (JsonNode utxoInfo : json) {

            Integer fundingOutputIndex = utxoInfo.get("tx_pos").asInt();
            String rawTxHex = utxoInfo.get("raw_tx").asText();
            BigInteger amount = BigInteger.valueOf(utxoInfo.get("value").asInt());

            Transaction fundingTx = Transaction.fromHex(rawTxHex);
            UnlockingScriptBuilder unlocker = new P2PKHUnlockBuilder(privateKey.getPublicKey());
            TransactionSigner signer = new TransactionSigner(SigHashType.ALL.value | SigHashType.FORKID.value, privateKey);

            builder.spendFromOutput(signer, fundingTx.getTransactionId(), fundingOutputIndex, amount, TransactionInput.MAX_SEQ_NUMBER, unlocker);

        }

        Address recipientAddress = Address.fromKey(NetworkAddressType.TEST_PKH, privateKey.getPublicKey());


        Assertions.assertThatCode(() -> {
            Transaction broadcastTx = builder.withFeePerKb(512)
                    .spendTo(new P2PKHLockBuilder(recipientAddress), BigInteger.valueOf(100000))
                    .sendChangeTo(recipientAddress)
                    .build(true);

            //new Script Interpreter to help us verify our spending conditions
            Interpreter interp = new Interpreter();

            //loop over every one of our spending inputs and verify we are
            //correctly spending those outputs
            for (int scriptSigIndex = 0; scriptSigIndex < 0; scriptSigIndex++) {
                TransactionInput spendingInputOne = TransactionInput.fromByteArray(broadcastTx.getInputs().get(0).serialize());
                String fundingTxId = Utils.HEX.encode(spendingInputOne.getPrevTxnId());
                Integer fundingOutputIndex = json.get(scriptSigIndex).get("tx_pos").asInt();
                Long fundingValue = json.get(scriptSigIndex).get("value").asLong();

                //lookup funding transaction corresponding to first output
                String rawFundingTx = json.get(scriptSigIndex).get("raw_tx").asText();
                Transaction fundingTxOne = Transaction.fromHex(rawFundingTx);
                TransactionOutput fundingOutput = fundingTxOne.getOutputs().get(fundingOutputIndex);

                TransactionSigner signer = new TransactionSigner(SigHashType.FORKID.value | SigHashType.ALL.value, privateKey);
                Transaction signedTx = signer.sign(broadcastTx, fundingOutput, scriptSigIndex);

                //assert that funding transaction is spending correctly
                Set<Script.VerifyFlag> verifyFlags = new HashSet<Script.VerifyFlag>(Arrays.asList(Script.VerifyFlag.SIGHASH_FORKID));
                interp.correctlySpends(signedTx.getInputs().get(scriptSigIndex).getScriptSig(), fundingOutput.getScript(), broadcastTx, scriptSigIndex, verifyFlags, Coin.valueOf(fundingValue));
            }
        }).doesNotThrowAnyException();

    }


    @Test
    public void builderCanSpendFromOutpoint() throws InvalidKeyException, IOException {

        //This WIF is for a private key that actually has testnet coins on TESTNET
        //The transactions in multi_input.json are UTXOs that exist(ed) on TESTNET
        // at time of writing this test, and can be viewed on TESTNET using a block explorer
        String wif = "cRTUuWgPdp7tJPrn1Xeq196eZa4ZCpg8n3cgDJsJmgDHBZ8x9fpv";
        PrivateKey privateKey = PrivateKey.fromWIF(wif);

        JsonNode json = new ObjectMapper().readTree(
                new InputStreamReader(getClass().getResourceAsStream("multi_input.json"),
                        StandardCharsets.UTF_8)
        );

        //build one large transaction that spends all the inputs
        TransactionBuilder builder = new TransactionBuilder();
        for (JsonNode utxoInfo : json) {

            Integer fundingOutputIndex = utxoInfo.get("tx_pos").asInt();
            String rawTxHex = utxoInfo.get("raw_tx").asText();
            BigInteger amount = BigInteger.valueOf(utxoInfo.get("value").asInt());

            Transaction fundingTx = Transaction.fromHex(rawTxHex);

            TransactionOutpoint outpoint = new TransactionOutpoint();
            outpoint.setTransactionId(fundingTx.getTransactionId());
            outpoint.setSatoshis(amount);
            outpoint.setOutputIndex(fundingOutputIndex);
            outpoint.setLockingScript(fundingTx.getOutputs().get(fundingOutputIndex).getScript());

            UnlockingScriptBuilder unlocker = new P2PKHUnlockBuilder(privateKey.getPublicKey());

            TransactionSigner signer = new TransactionSigner(SigHashType.ALL.value | SigHashType.FORKID.value, privateKey);

            builder.spendFromOutpoint(signer, outpoint, TransactionInput.MAX_SEQ_NUMBER, unlocker);

        }

        Address recipientAddress = Address.fromKey(NetworkAddressType.TEST_PKH, privateKey.getPublicKey());


        Assertions.assertThatCode(() -> {
            Transaction broadcastTx = builder.withFeePerKb(512)
                    .spendTo(new P2PKHLockBuilder(recipientAddress), BigInteger.valueOf(100000))
                    .sendChangeTo(recipientAddress)
                    .build(true);

            //new Script Interpreter to help us verify our spending conditions
            Interpreter interp = new Interpreter();

            //loop over every one of our spending inputs and verify we are
            //correctly spending those outputs
            for (int scriptSigIndex = 0; scriptSigIndex < 0; scriptSigIndex++) {
                TransactionInput spendingInputOne = TransactionInput.fromByteArray(broadcastTx.getInputs().get(0).serialize());
                String fundingTxId = Utils.HEX.encode(spendingInputOne.getPrevTxnId());
                Integer fundingOutputIndex = json.get(scriptSigIndex).get("tx_pos").asInt();
                Long fundingValue = json.get(scriptSigIndex).get("value").asLong();

                //lookup funding transaction corresponding to first output
                String rawFundingTx = json.get(scriptSigIndex).get("raw_tx").asText();
                Transaction fundingTxOne = Transaction.fromHex(rawFundingTx);
                TransactionOutput fundingOutput = fundingTxOne.getOutputs().get(fundingOutputIndex);

                TransactionSigner signer = new TransactionSigner(SigHashType.FORKID.value | SigHashType.ALL.value, privateKey);
                Transaction signedTx = signer.sign(broadcastTx, fundingOutput, scriptSigIndex);

                //assert that funding transaction is spending correctly
                Set<Script.VerifyFlag> verifyFlags = new HashSet<Script.VerifyFlag>(Arrays.asList(Script.VerifyFlag.SIGHASH_FORKID));
                interp.correctlySpends(signedTx.getInputs().get(scriptSigIndex).getScriptSig(), fundingOutput.getScript(), broadcastTx, scriptSigIndex, verifyFlags, Coin.valueOf(fundingValue));
            }
        }).doesNotThrowAnyException();
    }

    @Test
    public void builderCanSpendFromUtxoMap() throws InvalidKeyException, IOException {


        //This WIF is for a private key that actually has testnet coins on TESTNET
        //The transactions in multi_input.json are UTXOs that exist(ed) on TESTNET
        // at time of writing this test, and can be viewed on TESTNET using a block explorer
        String wif = "cRTUuWgPdp7tJPrn1Xeq196eZa4ZCpg8n3cgDJsJmgDHBZ8x9fpv";
        PrivateKey privateKey = PrivateKey.fromWIF(wif);

        System.out.println(Address.fromKey(NetworkAddressType.TEST_PKH, privateKey.getPublicKey()).toString());
        JsonNode json = new ObjectMapper().readTree(
                new InputStreamReader(getClass().getResourceAsStream("multi_input.json"),
                        StandardCharsets.UTF_8)
        );

        //build one large transaction that spends all the inputs
        TransactionBuilder builder = new TransactionBuilder();
        for (JsonNode utxoInfo : json) {

            Integer fundingOutputIndex = utxoInfo.get("tx_pos").asInt();
            String rawTxHex = utxoInfo.get("raw_tx").asText();
            BigInteger amount = BigInteger.valueOf(utxoInfo.get("value").asInt());

            Transaction fundingTx = Transaction.fromHex(rawTxHex);

            HashMap utxoMap = new HashMap();
            utxoMap.put("transactionId", fundingTx.getTransactionId());
            utxoMap.put("satoshis", amount);
            utxoMap.put("sequenceNumber", TransactionInput.MAX_SEQ_NUMBER);
            utxoMap.put("outputIndex", fundingOutputIndex);
            utxoMap.put("scriptPubKey", Utils.HEX.encode(fundingTx.getOutputs().get(fundingOutputIndex).serialize()));

            UnlockingScriptBuilder unlocker = new P2PKHUnlockBuilder(privateKey.getPublicKey());

            TransactionSigner signer = new TransactionSigner(SigHashType.ALL.value | SigHashType.FORKID.value, privateKey);
            builder.spendFromUtxoMap(signer, utxoMap, unlocker);

        }

        Address recipientAddress = Address.fromKey(NetworkAddressType.TEST_PKH, privateKey.getPublicKey());


        Assertions.assertThatCode(() -> {
            Transaction broadcastTx = builder.withFeePerKb(512)
                    .spendTo(new P2PKHLockBuilder(recipientAddress), BigInteger.valueOf(100000))
                    .sendChangeTo(recipientAddress)
                    .build(true);

            //new Script Interpreter to help us verify our spending conditions
            Interpreter interp = new Interpreter();

            //loop over every one of our spending inputs and verify we are
            //correctly spending those outputs
            for (int scriptSigIndex = 0; scriptSigIndex < 0; scriptSigIndex++) {
                TransactionInput spendingInputOne = TransactionInput.fromByteArray(broadcastTx.getInputs().get(0).serialize());
                String fundingTxId = Utils.HEX.encode(spendingInputOne.getPrevTxnId());
                Integer fundingOutputIndex = json.get(scriptSigIndex).get("tx_pos").asInt();
                Long fundingValue = json.get(scriptSigIndex).get("value").asLong();

                //lookup funding transaction corresponding to first output
                String rawFundingTx = json.get(scriptSigIndex).get("raw_tx").asText();
                Transaction fundingTxOne = Transaction.fromHex(rawFundingTx);
                TransactionOutput fundingOutput = fundingTxOne.getOutputs().get(fundingOutputIndex);

                TransactionSigner signer = new TransactionSigner(SigHashType.FORKID.value | SigHashType.ALL.value, privateKey);
                Transaction signedTx = signer.sign(broadcastTx, fundingOutput, scriptSigIndex);

                //assert that funding transaction is spending correctly
                Set<Script.VerifyFlag> verifyFlags = new HashSet<Script.VerifyFlag>(Arrays.asList(Script.VerifyFlag.SIGHASH_FORKID));
                interp.correctlySpends(signedTx.getInputs().get(scriptSigIndex).getScriptSig(), fundingOutput.getScript(), broadcastTx, scriptSigIndex, verifyFlags, Coin.valueOf(fundingValue));
            }
        }).doesNotThrowAnyException();
    }

    @Test
    public void canSpendMultipleOutputsFromSameTx() throws MnemonicException, IOException, InvalidKeyException, TransactionException, SigHashException, SignatureDecodeException {

        PrivateKey pkOne = PrivateKey.fromWIF("L14C38sujYefjpj4Zj5HTwjaHAZKMSLZZAnzLNojC8CmU8Q4TpWE");
        PrivateKey pkTwo = PrivateKey.fromWIF("L4YDdzJa5Ae2ukENpPqFBPCutM1xsM9WvKFy6Bugv4iyg6U4c2kE");

        TransactionBuilder builder = new TransactionBuilder();
        builder.withFeePerKb(512);

        String rawFundingTx = "0100000001c5d4b2f482627e7c46ad977cbacf9bfdf2197229952daa3a4b57d15fccfad92b000000006a47304402207927136ea0b51fc9a2cb883ac2a72410dec41bef98062b7845eac691cc2c9f6602202b8b370b588542941623379a046e5aea654b1edd5c9c074a426b1be45545ed5d412103c36ea9ccb9a332b415ebf9e9823e2b352f2ed2c4199ea382cf98ddbfcf4eed24ffffffff02204e0000000000001976a914eb6edc362ae7e5d2765e86a97741722b0f7e20d688ac260c0300000000001976a914cd1a22818d1f143b152276ee6a69486233405d3e88ac00000000";
        Transaction fundingTx = Transaction.fromHex(rawFundingTx);

        P2PKHUnlockBuilder unlockOne = new P2PKHUnlockBuilder(pkOne.getPublicKey());
        TransactionSigner signerOne = new TransactionSigner(SigHashType.ALL.value | SigHashType.FORKID.value, pkOne);
        builder.spendFromTransaction(signerOne, fundingTx, 0, TransactionInput.MAX_SEQ_NUMBER, unlockOne);

        P2PKHUnlockBuilder unlockTwo = new P2PKHUnlockBuilder(pkTwo.getPublicKey());
        TransactionSigner signerTwo = new TransactionSigner(SigHashType.ALL.value | SigHashType.FORKID.value, pkTwo);
        builder.spendFromTransaction(signerTwo, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, unlockTwo);

        //send back to the first key
        Address recipientAddress = Address.fromKey(NetworkAddressType.MAIN_PKH, pkOne.getPublicKey());
        P2PKHLockBuilder lockBuilder = new P2PKHLockBuilder(recipientAddress);
        builder.spendTo(lockBuilder, BigInteger.valueOf(20000));

        //send change to second key
        Address changeAddress = Address.fromKey(NetworkAddressType.MAIN_PKH, pkTwo.getPublicKey());
        builder.sendChangeTo(changeAddress);

        Transaction broadcastTx = builder.build(true);

        Assertions.assertThatCode(() -> {

            //new Script Interpreter to help us verify our spending conditions
            Interpreter interp = new Interpreter();
            Set<Script.VerifyFlag> verifyFlags = new HashSet<Script.VerifyFlag>(Arrays.asList(Script.VerifyFlag.SIGHASH_FORKID));


//            ////FIRST UTXO
            Integer fundingOutputIndexOne = 0;
            Long fundingValueOne = 20000L;

            //lookup funding transaction corresponding to first output
            TransactionOutput fundingOutput = fundingTx.getOutputs().get(fundingOutputIndexOne);

            //assert that funding transaction is spending correctly
            interp.correctlySpends(broadcastTx.getInputs().get(0).getScriptSig(), fundingOutput.getScript(), broadcastTx, 0, verifyFlags, Coin.valueOf(fundingValueOne));

            ////SECOND UTXO
//            TransactionInput spendingInputTwo = TransactionInput.fromByteArray(broadcastTx.getInputs().get(1).serialize());
            Integer fundingOutputIndexTwo = 1;
            Long fundingValueTwo = 199718L;

            //lookup funding transaction corresponding to first output
            TransactionOutput fundingOutputTwo = fundingTx.getOutputs().get(fundingOutputIndexTwo);

            Transaction signedTxTwo = signerTwo.sign(broadcastTx, fundingOutputTwo, 1);

            //assert that funding transaction is spending correctly
            interp.correctlySpends(broadcastTx.getInputs().get(1).getScriptSig(), fundingOutputTwo.getScript(), broadcastTx, 1, verifyFlags, Coin.valueOf(fundingValueTwo));

        }).doesNotThrowAnyException();

    }

}
