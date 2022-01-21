package org.twostack.bitcoin4j.transaction;

import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.twostack.bitcoin4j.Address;
import org.twostack.bitcoin4j.PrivateKey;
import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.exception.InvalidKeyException;
import org.twostack.bitcoin4j.exception.SigHashException;
import org.twostack.bitcoin4j.exception.SignatureDecodeException;
import org.twostack.bitcoin4j.exception.TransactionException;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.bitcoin4j.params.NetworkType;
import org.twostack.bitcoin4j.script.*;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.*;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.*;

public class LockUnlockBuilderTests {

    Address changeAddress = Address.fromString(NetworkType.TEST, "mu4DpTaD75nheE4z5CQazqm1ivej1vzL4L"); // my address
    Address recipientAddress = Address.fromString(NetworkType.TEST, "n3aZKucfWmXeXhX13MREQQnqNfbrWiYKtg"); //bitcoin-cli address

    PrivateKey privateKey = PrivateKey.fromWIF("KwoVx4zhcVeXqjGCk4nYGxk2EGP7PGqQUdmRBpKGHfFWmMPzTqZu");
    PublicKey publicKey = privateKey.getPublicKey();

    Address address = Address.fromKey(NetworkAddressType.TEST_PKH, privateKey.getPublicKey());
    String pubkeyScript = "OP_PUSHDATA1 32 0x2606168dabed7b4d11fdd242317adb480ee8c4fa7330db1a8b4f1c7749072aea OP_DROP OP_DUP OP_HASH160 20 0x581e5e328b0d34d724c09f123c050b341d11d96c OP_EQUALVERIFY OP_CHECKSIG";
    String coinbaseOutput = "02000000016b748661a108dc35d8868a9a552b9364c6ee3f06a4604f722882d49cdc4d13020000000048473044022073062451397fb5e7e2e02f1603e2a92677d516a5e747b1ae2ad0996387916d4302200ae2ec97d4525621cef07f75f0b92b5e83341761fa604c83daf0390a76d5024241feffffff0200e1f505000000001976a91494837d2d5d6106aa97db38957dcc294181ee91e988ac00021024010000001976a9144d991c88b4fd954ea62aa7182d3b3e251896a83188acd5000000";

    byte[] smallTestData = Utils.HEX.decode("02000000016b748661a108dc35d8868a9a552b9364c6ee3f");
    byte[] largeTestData = Utils.HEX.decode("02000000016b748661a108dc35d8868a9a552b9364c6ee3f06a4604f722882d49cdc4d13020000000048473044022073062451397fb5e7e2e02f1603e2a92677d516a5e747b1ae2ad0996387916d4302200ae2ec97d4525621cef07f75f0b92b5e83341761fa604c83daf0390a76d5024241feffffff0200e1f505000000001976a91494837d2d5d6106aa97db38957dcc294181ee91e988ac00021024010000001976a9144d991c88b4fd954ea62aa7182d3b3e251896a83188acd5000000");

    List<String> pubKeyHexes = Arrays.asList(new String[]{
            "022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da",
            "03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9",
            "021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18",
            "02bf97f572a02a8900246d72c2e8fa3d3798a6e59c4e17de2d131d9c60d0d9b574",
            "036a98a36aa7665874b1ba9130bc6d318e52fd3bdb5969532d7fc09bf2476ff842",
            "033aafcbead78c08b0e0aacc1b0cdb40702a7c709b660bebd286e973242127e15b"
    });

    List<PublicKey> sortkeys = pubKeyHexes.subList(0, 3).stream().map( (hexKey) -> PublicKey.fromHex(hexKey)).collect(Collectors.toList());

    public LockUnlockBuilderTests() throws InvalidKeyException {
    }


    @Test
    public void testCreateSpendableDataLockerFromSmallData() throws IOException {

        Address address = Address.fromKey(NetworkAddressType.TEST_PKH, privateKey.getPublicKey());
        P2PKHDataLockBuilder lockBuilder = new P2PKHDataLockBuilder(address, ByteBuffer.wrap(smallTestData));

//        var scriptString = 'OP_PUSHDATA1 32 0x${commitHash} OP_DROP OP_DUP OP_HASH160 20 0x581e5e328b0d34d724c09f123c050b341d11d96c OP_EQUAL';
        Script script = lockBuilder.getLockingScript();

        List<ScriptChunk> chunks = script.getChunks();

        assertEquals(7, chunks.size());
        assertEquals(ScriptOpCodes.OP_DROP, chunks.get(1).opcode);
        assertEquals(ScriptOpCodes.OP_DUP, chunks.get(2).opcode);
        assertEquals(ScriptOpCodes.OP_HASH160, chunks.get(3).opcode);

        assertEquals(Utils.HEX.encode(lockBuilder.getDataBuffer().array()), "02000000016b748661a108dc35d8868a9a552b9364c6ee3f");

        //roundtrip it
        String scriptString = "24 0x02000000016b748661a108dc35d8868a9a552b9364c6ee3f OP_DROP OP_DUP OP_HASH160 20 0x2279837529828be4ae0110939ddbb8c15821cf50 OP_EQUALVERIFY OP_CHECKSIG";

        Script lockingScript = Script.fromBitcoindString(scriptString);
        P2PKHDataLockBuilder lockBuilder2 = new P2PKHDataLockBuilder(lockingScript);

        assertEquals(Utils.HEX.encode(lockBuilder2.getDataBuffer().array()), "02000000016b748661a108dc35d8868a9a552b9364c6ee3f");
    }

    @Test
    public void testCreateSpendableDataLockerFromLargeData() throws IOException {

        P2PKHDataLockBuilder lockBuilder = new P2PKHDataLockBuilder(address, ByteBuffer.wrap(largeTestData));

        Script script = lockBuilder.getLockingScript();

        List<ScriptChunk> chunks = script.getChunks();

        System.out.println(script.toBitcoindString());
        assertEquals(7, chunks.size());
        assertEquals(ScriptOpCodes.OP_DROP, chunks.get(1).opcode);
        assertEquals(ScriptOpCodes.OP_DUP, chunks.get(2).opcode);
        assertEquals(ScriptOpCodes.OP_HASH160, chunks.get(3).opcode);

        assertEquals(Utils.HEX.encode(lockBuilder.getDataBuffer().array()), "02000000016b748661a108dc35d8868a9a552b9364c6ee3f06a4604f722882d49cdc4d13020000000048473044022073062451397fb5e7e2e02f1603e2a92677d516a5e747b1ae2ad0996387916d4302200ae2ec97d4525621cef07f75f0b92b5e83341761fa604c83daf0390a76d5024241feffffff0200e1f505000000001976a91494837d2d5d6106aa97db38957dcc294181ee91e988ac00021024010000001976a9144d991c88b4fd954ea62aa7182d3b3e251896a83188acd5000000");

        //roundtrip it
        String scriptString = "OP_PUSHDATA1 191 0x02000000016b748661a108dc35d8868a9a552b9364c6ee3f06a4604f722882d49cdc4d13020000000048473044022073062451397fb5e7e2e02f1603e2a92677d516a5e747b1ae2ad0996387916d4302200ae2ec97d4525621cef07f75f0b92b5e83341761fa604c83daf0390a76d5024241feffffff0200e1f505000000001976a91494837d2d5d6106aa97db38957dcc294181ee91e988ac00021024010000001976a9144d991c88b4fd954ea62aa7182d3b3e251896a83188acd5000000 OP_DROP OP_DUP OP_HASH160 20 0x2279837529828be4ae0110939ddbb8c15821cf50 OP_EQUALVERIFY OP_CHECKSIG";

        Script lockingScript = Script.fromBitcoindString(scriptString);
        P2PKHDataLockBuilder lockBuilder2 = new P2PKHDataLockBuilder(lockingScript);

        assertEquals(Utils.HEX.encode(lockBuilder2.getDataBuffer().array()), "02000000016b748661a108dc35d8868a9a552b9364c6ee3f06a4604f722882d49cdc4d13020000000048473044022073062451397fb5e7e2e02f1603e2a92677d516a5e747b1ae2ad0996387916d4302200ae2ec97d4525621cef07f75f0b92b5e83341761fa604c83daf0390a76d5024241feffffff0200e1f505000000001976a91494837d2d5d6106aa97db38957dcc294181ee91e988ac00021024010000001976a9144d991c88b4fd954ea62aa7182d3b3e251896a83188acd5000000");
    }

    @Test
    public void cannotCreateEmptyDataScript() {
      assertThrows(ScriptException.class, () -> new UnspendableDataLockBuilder(new ScriptBuilder().build()));
    }

    @Test
    public void canHandleLargeDataPush(){
      String dataString = "3046022100bb3c194a30e460d81d34be0a230179c043a656f67e3c5c8bf47eceae7c4042ee0221008bf54ca11b2985285be0fd7a212873d243e6e73f5fad57e8eb14c4f39728b8c601";

      List<ByteBuffer> dataList = new ArrayList<ByteBuffer>();
      dataList.add(ByteBuffer.wrap(dataString.getBytes(Charset.forName("UTF-8"))));

      Assertions.assertThatCode( () -> new UnspendableDataLockBuilder(dataList)).doesNotThrowAnyException();
    }

    @Test
    public void failsOnOldStyleOpReturn() throws IOException {
        Script returnScript = Script.fromBitcoindString("OP_RETURN");
        assertThrows(ScriptException.class, () -> new UnspendableDataLockBuilder(returnScript));

    }

    @Test
    public void canCreateNewStyleOpReturn() throws IOException {
        Script returnScript = Script.fromBitcoindString("OP_0 OP_RETURN");
        Assertions.assertThatCode(() -> new UnspendableDataLockBuilder(returnScript)).doesNotThrowAnyException();
    }

    @Test
    public void canCreateDataScript(){
        ByteBuffer byteBuffer = ByteBuffer.wrap(Utils.HEX.decode("bacacafe0102030405"));

        List<ByteBuffer> dataList = new ArrayList<>();
        dataList.add(byteBuffer);

        LockingScriptBuilder lockBuilder = new UnspendableDataLockBuilder(dataList);

        assertEquals("OP_0 OP_RETURN 9 0xbacacafe0102030405", lockBuilder.getLockingScript().toBitcoindString());
    }
    //TODO: Add tests for other pushdata sizes

    @Test
    public void canCreateP2PKHScript(){
        PublicKey pubkey = PublicKey.fromHex( "022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da");

        LockingScriptBuilder lockBuilder = new P2PKLockBuilder(pubkey);
        Script script = lockBuilder.getLockingScript();
        assertNotNull(script);
        assertEquals( "33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da OP_CHECKSIG", script.toBitcoindString());
    }

    @Test
    public void canUseP2PKInTransactionBuilder() throws InvalidKeyException, TransactionException, SigHashException, SignatureDecodeException, IOException {

        //Create a Transaction instance from the RAW transaction data create by bitcoin-cli.
        //this transaction contains the UTXO we are interested in
        Transaction txWithUTXO = Transaction.fromHex(coinbaseOutput);

        //Let's create the set of Spending Transaction Inputs. These Transaction Inputs need to refer to the Outputs in
        //the Transaction we are spending from.

        P2PKLockBuilder locker = new P2PKLockBuilder(publicKey);
        P2PKHUnlockBuilder unlocker = new P2PKHUnlockBuilder(privateKey.getPublicKey());
        Transaction unsignedTxn = new TransactionBuilder()
                .spendFromTransaction(txWithUTXO, 0, Transaction.NLOCKTIME_MAX_VALUE, unlocker) //set global sequenceNumber/nLocktime time for each Input created
                .spendTo(locker, BigInteger.valueOf(50000000L)) //spend half of a bitcoin (we should have 1 in the UTXO)
                .sendChangeTo(locker) // spend change to myself
                .withFeePerKb(512)
                .build(true);

        TransactionOutput utxoToSign = txWithUTXO.getOutputs().get(0);

        //simply check that we have clean e2e execution
        Assertions.assertThatCode(() -> {
            TransactionSigner signer = new TransactionSigner( SigHashType.ALL.value | SigHashType.FORKID.value, privateKey);
            signer.sign(unsignedTxn, utxoToSign,0);
        }).doesNotThrowAnyException();
    }

    @Test
    public void canCreateP2PKHScriptFromMainnetAddress() {
        Address address = Address.fromString(NetworkType.MAIN, "1NaTVwXDDUJaXDQajoa9MqHhz4uTxtgK14");
        P2PKHLockBuilder lockBulder = new P2PKHLockBuilder(address);
        Script script = lockBulder.getLockingScript();
        assertNotNull(script);
        assertEquals("OP_DUP OP_HASH160 20 0xecae7d092947b7ee4998e254aa48900d26d2ce1d OP_EQUALVERIFY OP_CHECKSIG", script.toBitcoindString());
        assertEquals(lockBulder.getAddress().toString(), "1NaTVwXDDUJaXDQajoa9MqHhz4uTxtgK14");
    }

    @Test
    public void canCreateP2PKHScriptFromPublicKey(){
        PublicKey pubkey = PublicKey.fromHex( "022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da");

        P2PKHLockBuilder lockBuilder = P2PKHLockBuilder.fromPublicKey(pubkey, NetworkAddressType.TEST_PKH);
        Script script = lockBuilder.getLockingScript();
        assertNotNull(script);
        assertEquals("OP_DUP OP_HASH160 20 0x9674af7395592ec5d91573aa8d6557de55f60147 OP_EQUALVERIFY OP_CHECKSIG",   script.toBitcoindString());
        assertEquals(lockBuilder.getAddress().getNetworkType(), NetworkType.TEST);

    }

    @Test
    public void canDeserializeUnlockingScript() throws SignatureDecodeException, IOException {

        PublicKey pubkey = PublicKey.fromHex("04e365859b3c78a8b7c202412b949ebca58e147dba297be29eee53cd3e1d300a6419bc780cc9aec0dc94ed194e91c8f6433f1b781ee00eac0ead2aae1e8e0712c6");
        TransactionSignature signature = TransactionSignature.fromTxFormat("3046022100bb3c194a30e460d81d34be0a230179c043a656f67e3c5c8bf47eceae7c4042ee0221008bf54ca11b2985285be0fd7a212873d243e6e73f5fad57e8eb14c4f39728b8c601");
        Script script = Script.fromBitcoindString("73 0x3046022100bb3c194a30e460d81d34be0a230179c043a656f67e3c5c8bf47eceae7c4042ee0221008bf54ca11b2985285be0fd7a212873d243e6e73f5fad57e8eb14c4f39728b8c601 65 0x04e365859b3c78a8b7c202412b949ebca58e147dba297be29eee53cd3e1d300a6419bc780cc9aec0dc94ed194e91c8f6433f1b781ee00eac0ead2aae1e8e0712c6");

        P2PKHUnlockBuilder unlockBuilder= new P2PKHUnlockBuilder(script);

        assertFalse(unlockBuilder.signatures.isEmpty());
        assertNotNull(unlockBuilder.getSignerPubkey());
        assertEquals(pubkey.getPubKeyHex(), unlockBuilder.getSignerPubkey().getPubKeyHex());
        assertEquals(unlockBuilder.getSignatures().get(0).toString(), signature.toString());
    }

    @Test
    public void canCreateScriptPubkeyFromHash() throws IOException {

        Script inner = Script.fromBitcoindString("OP_DUP OP_HASH160 20 0x06c06f6d931d7bfba2b5bd5ad0d19a8f257af3e3 OP_EQUALVERIFY OP_CHECKSIG");
        byte[] scriptHash = Utils.sha256hash160(inner.getProgram());
        P2SHLockBuilder lockBuilder = new P2SHLockBuilder(ByteBuffer.wrap(scriptHash));
        Script script = lockBuilder.getLockingScript();
        assertNotNull(script);
        assertEquals("OP_HASH160 20 0x45ea3f9133e7b1cef30ba606f8433f993e41e159 OP_EQUAL", script.toBitcoindString());

    }

    @Test
    public void createsP2SHLockingScriptFromScript() throws IOException {
        Script inner = Script.fromBitcoindString("OP_DUP OP_HASH160 20 0x06c06f6d931d7bfba2b5bd5ad0d19a8f257af3e3 OP_EQUALVERIFY OP_CHECKSIG");
        P2SHLockBuilder lockBuilder = new P2SHLockBuilder(inner);
        Script script = lockBuilder.getLockingScript();
        assertNotNull(script);
        assertEquals("OP_HASH160 20 0x45ea3f9133e7b1cef30ba606f8433f993e41e159 OP_EQUAL", script.toBitcoindString());

    }

    @Test
    public void canSortKeysInP2MS(){

        P2MSLockBuilder lockBuilder = new P2MSLockBuilder(sortkeys, 2, true);
        Script script = lockBuilder.getLockingScript();
        assertEquals( "OP_2 33 0x021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18 33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da 33 0x03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9 OP_3 OP_CHECKMULTISIG", script.toBitcoindString() );
    }

    @Test
    public void shouldFailIfNotEnoughPubkeys(){
        assertEquals(3, sortkeys.size());
        P2MSLockBuilder lockBuilder = new P2MSLockBuilder(sortkeys, 4);
        assertThrows(ScriptException.class, () -> lockBuilder.getLockingScript());

    }

    @Test
    public void canCreateUnsortedScript(){
        P2MSLockBuilder lockBuilder = new P2MSLockBuilder(sortkeys, 2);
        P2MSLockBuilder unsortedLockBuilder = new P2MSLockBuilder(sortkeys, 2, false);
        Script sortedScript = lockBuilder.getLockingScript();
        Script unsortedScript = unsortedLockBuilder.getLockingScript();

        assertNotEquals(sortedScript.toBitcoindString(), unsortedScript.toBitcoindString());
        assertEquals("OP_2 33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da 33 0x03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9 33 0x021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18 OP_3 OP_CHECKMULTISIG", unsortedScript.toBitcoindString());

    }

    @Test
    public void canRecoverStateFromScript() throws IOException {
        Script script = Script.fromBitcoindString("OP_2 33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da 33 0x03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9 33 0x021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18 OP_3 OP_CHECKMULTISIG");
//        Script script = Script.fromBitcoindString("2 33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da 33 0x03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9 2 CHECKMULTISIG");

        P2MSLockBuilder lockBuilder = new P2MSLockBuilder(script);

        assertEquals(3,lockBuilder.getPublicKeys().size());
        assertEquals(2, lockBuilder.getRequiredSigs());
        assertEquals("022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da", lockBuilder.getPublicKeys().get(0).getPubKeyHex());
        assertEquals("03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9", lockBuilder.getPublicKeys().get(1).getPubKeyHex());
    }

    @Test
    public void canUnlockP2MS() throws IOException {

        Script script = Script.fromBitcoindString("OP_0 71 0x3044022002a27769ee33db258bdf7a3792e7da4143ec4001b551f73e6a190b8d1bde449d02206742c56ccd94a7a2e16ca52fc1ae4a0aa122b0014a867a80de104f9cb18e472c01 72 0x30450220357011fd3b3ad2b8f2f2d01e05dc6108b51d2a245b4ef40c112d6004596f0475022100a8208c93a39e0c366b983f9a80bfaf89237fcd64ca543568badd2d18ee2e1d7501");
        P2MSUnlockBuilder unlockBuilder = new P2MSUnlockBuilder(script);

        assertEquals(2, unlockBuilder.getSignatures().size());
        assertEquals( "3044022002a27769ee33db258bdf7a3792e7da4143ec4001b551f73e6a190b8d1bde449d02206742c56ccd94a7a2e16ca52fc1ae4a0aa122b0014a867a80de104f9cb18e472c01", Utils.HEX.encode(unlockBuilder.getSignatures().get(0).toTxFormat()));
        assertEquals("30450220357011fd3b3ad2b8f2f2d01e05dc6108b51d2a245b4ef40c112d6004596f0475022100a8208c93a39e0c366b983f9a80bfaf89237fcd64ca543568badd2d18ee2e1d7501", Utils.HEX.encode(unlockBuilder.getSignatures().get(1).toTxFormat()));
    }






    @Test
    public void canSpendFromMultiSig() throws InvalidKeyException, TransactionException, SigHashException, IOException, SignatureDecodeException {
        Address fromAddress = Address.fromString(NetworkType.TEST, "mszYqVnqKoQx4jcTdJXxwKAissE3Jbrrc1");
        Address toAddress = Address.fromString(NetworkType.TEST, "mrU9pEmAx26HcbKVrABvgL7AwA5fjNFoDc");
        PrivateKey private1 = PrivateKey.fromWIF( "cSBnVM4xvxarwGQuAfQFwqDg9k5tErHUHzgWsEfD4zdwUasvqRVY");
        PrivateKey private2 = PrivateKey.fromWIF( "cVVvUsNHhbrgd7aW3gnuGo2qJM45LhHhTCVXrDSJDDcNGE6qmyCs");
        PublicKey public1 = private1.getPublicKey();
        PublicKey public2 = private2.getPublicKey();
        P2MSLockBuilder lockBuilder = new P2MSLockBuilder(Arrays.asList(new PublicKey[]{public1, public2}), 2);

        P2MSUnlockBuilder unlockBuilder = new P2MSUnlockBuilder();
        Transaction tx = new TransactionBuilder()
            .spendFromOutput(
                    "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458",
                    0,
                    BigInteger.valueOf(100000), 0,
                    unlockBuilder)
            .spendTo(new P2PKHLockBuilder(toAddress), BigInteger.valueOf(50000))
            .sendChangeTo(changeAddress)
            .withFeePerKb(512)
            .build(false);

        TransactionSigner signer1 = new TransactionSigner(SigHashType.ALL.value | SigHashType.FORKID.value, private1 );
        TransactionSigner signer2 = new TransactionSigner(SigHashType.ALL.value | SigHashType.FORKID.value, private2 );
        TransactionOutput utxo = new TransactionOutput(BigInteger.valueOf(100000), lockBuilder);
        signer1.sign(tx, utxo, 0);
        signer2.sign(tx, utxo, 0);

        assertEquals(2, unlockBuilder.getSignatures().size() );

        Interpreter interpreter = new Interpreter();
        //interpreter.correctlySpends(); FIXME: perform this check to see if the interpreter validates our TX
    }

}
