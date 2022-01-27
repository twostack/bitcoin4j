package org.twostack.bitcoin4j.transaction;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.twostack.bitcoin4j.Address;
import org.twostack.bitcoin4j.Coin;
import org.twostack.bitcoin4j.PrivateKey;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.exception.InvalidKeyException;
import org.twostack.bitcoin4j.exception.SigHashException;
import org.twostack.bitcoin4j.exception.SignatureDecodeException;
import org.twostack.bitcoin4j.exception.TransactionException;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.bitcoin4j.script.Interpreter;
import org.twostack.bitcoin4j.script.Script;

import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

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
            builder.spendFromUtxoMap(signer, utxoMap,  unlocker);

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
}
