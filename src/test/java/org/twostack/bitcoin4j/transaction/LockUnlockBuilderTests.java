package org.twostack.bitcoin4j.transaction;

import org.junit.Test;
import org.twostack.bitcoin4j.Address;
import org.twostack.bitcoin4j.PrivateKey;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.exception.InvalidKeyException;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptChunk;
import org.twostack.bitcoin4j.script.ScriptOpCodes;

import java.nio.ByteBuffer;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class LockUnlockBuilderTests {

    PrivateKey privateKey = PrivateKey.fromWIF("KwoVx4zhcVeXqjGCk4nYGxk2EGP7PGqQUdmRBpKGHfFWmMPzTqZu");
    String pubkeyScript = "OP_PUSHDATA1 32 0x2606168dabed7b4d11fdd242317adb480ee8c4fa7330db1a8b4f1c7749072aea OP_DROP OP_DUP OP_HASH160 20 0x581e5e328b0d34d724c09f123c050b341d11d96c OP_EQUALVERIFY OP_CHECKSIG";

    byte[] smallTestData = Utils.HEX.decode("02000000016b748661a108dc35d8868a9a552b9364c6ee3f");
    byte[] largeTestData = Utils.HEX.decode("02000000016b748661a108dc35d8868a9a552b9364c6ee3f06a4604f722882d49cdc4d13020000000048473044022073062451397fb5e7e2e02f1603e2a92677d516a5e747b1ae2ad0996387916d4302200ae2ec97d4525621cef07f75f0b92b5e83341761fa604c83daf0390a76d5024241feffffff0200e1f505000000001976a91494837d2d5d6106aa97db38957dcc294181ee91e988ac00021024010000001976a9144d991c88b4fd954ea62aa7182d3b3e251896a83188acd5000000");

    public LockUnlockBuilderTests() throws InvalidKeyException {
    }


    @Test
    public void testCreateSpendableDataLockerFromSmallData(){

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
        String scriptString = "24 0x02000000016b748661a108dc35d8868a9a552b9364c6ee3f DROP DUP HASH160 20 0x2279837529828be4ae0110939ddbb8c15821cf50 EQUALVERIFY CHECKSIG";

        Script lockingScript = Script.fromAsmString(scriptString);
        P2PKHDataLockBuilder lockBuilder2 = new P2PKHDataLockBuilder(lockingScript);

        assertEquals(Utils.HEX.encode(lockBuilder2.getDataBuffer().array()), "02000000016b748661a108dc35d8868a9a552b9364c6ee3f");
    }

    @Test
    public void testCreateSpendableDataLockerFromLargeData(){

        Address address = Address.fromKey(NetworkAddressType.TEST_PKH, privateKey.getPublicKey());
        P2PKHDataLockBuilder lockBuilder = new P2PKHDataLockBuilder(address, ByteBuffer.wrap(largeTestData));

        Script script = lockBuilder.getLockingScript();

        List<ScriptChunk> chunks = script.getChunks();

        System.out.println(script.toAsmString());
        assertEquals(7, chunks.size());
        assertEquals(ScriptOpCodes.OP_DROP, chunks.get(1).opcode);
        assertEquals(ScriptOpCodes.OP_DUP, chunks.get(2).opcode);
        assertEquals(ScriptOpCodes.OP_HASH160, chunks.get(3).opcode);

        assertEquals(Utils.HEX.encode(lockBuilder.getDataBuffer().array()), "02000000016b748661a108dc35d8868a9a552b9364c6ee3f06a4604f722882d49cdc4d13020000000048473044022073062451397fb5e7e2e02f1603e2a92677d516a5e747b1ae2ad0996387916d4302200ae2ec97d4525621cef07f75f0b92b5e83341761fa604c83daf0390a76d5024241feffffff0200e1f505000000001976a91494837d2d5d6106aa97db38957dcc294181ee91e988ac00021024010000001976a9144d991c88b4fd954ea62aa7182d3b3e251896a83188acd5000000");

        //roundtrip it
        String scriptString = "PUSHDATA1 191 0x02000000016b748661a108dc35d8868a9a552b9364c6ee3f06a4604f722882d49cdc4d13020000000048473044022073062451397fb5e7e2e02f1603e2a92677d516a5e747b1ae2ad0996387916d4302200ae2ec97d4525621cef07f75f0b92b5e83341761fa604c83daf0390a76d5024241feffffff0200e1f505000000001976a91494837d2d5d6106aa97db38957dcc294181ee91e988ac00021024010000001976a9144d991c88b4fd954ea62aa7182d3b3e251896a83188acd5000000 DROP DUP HASH160 20 0x2279837529828be4ae0110939ddbb8c15821cf50 EQUALVERIFY CHECKSIG";

        Script lockingScript = Script.fromAsmString(scriptString);
        P2PKHDataLockBuilder lockBuilder2 = new P2PKHDataLockBuilder(lockingScript);

        assertEquals(Utils.HEX.encode(lockBuilder2.getDataBuffer().array()), "02000000016b748661a108dc35d8868a9a552b9364c6ee3f06a4604f722882d49cdc4d13020000000048473044022073062451397fb5e7e2e02f1603e2a92677d516a5e747b1ae2ad0996387916d4302200ae2ec97d4525621cef07f75f0b92b5e83341761fa604c83daf0390a76d5024241feffffff0200e1f505000000001976a91494837d2d5d6106aa97db38957dcc294181ee91e988ac00021024010000001976a9144d991c88b4fd954ea62aa7182d3b3e251896a83188acd5000000");
    }

    /*

  test('can parse a locking script', (){

    PedersenCommitLockBuilder lockBuilder = PedersenCommitLockBuilder.fromScript(SVScript.fromString(pubkeyScript));

    //check commitment
    expect(lockBuilder.commitHash, equals('2606168dabed7b4d11fdd242317adb480ee8c4fa7330db1a8b4f1c7749072aea'));

    //check address
    var address = privateKey.toAddress(networkType: NetworkType.TEST);
    var addressHash = HEX.encode(hash160(HEX.decode(address.toHex())));
    expect(lockBuilder.addressHash , equals(addressHash));
  });


  group('building data output scripts', () {
    test('should create script from no data', () {
      var lockBuilder = DataLockBuilder(null);
      expect(lockBuilder.getScriptPubkey().toString(), equals('OP_0 OP_RETURN'));
    });

    test('should create script from empty data', () {
      var lockBuilder = DataLockBuilder(utf8.encode(''));
      expect(lockBuilder.getScriptPubkey().toString(), equals('OP_0 OP_RETURN'));
      expect(lockBuilder.getScriptPubkey().toString(), equals('OP_0 OP_RETURN'));
    });

    test('can handle larger data pushes', (){
      var data = "3046022100bb3c194a30e460d81d34be0a230179c043a656f67e3c5c8bf47eceae7c4042ee0221008bf54ca11b2985285be0fd7a212873d243e6e73f5fad57e8eb14c4f39728b8c601";

      var lockBuilder = DataLockBuilder(utf8.encode(data));
      expect(() => lockBuilder.getScriptPubkey(), returnsNormally);
    });


    test('fails if old-style OP_RETURN', () {
      var lockBuilder = DataLockBuilder(null);

      var script = SVScript.fromString('OP_RETURN');
      expect(() => lockBuilder.fromScript(script), throwsException);
    });

    test('should create script from some data', () {
      var data = HEX.decode('bacacafe0102030405');

      var lockBuilder = DataLockBuilder(data);
      var scriptPubkey = lockBuilder.getScriptPubkey();
      expect(scriptPubkey.toString(), equals('OP_0 OP_RETURN 9 0xbacacafe0102030405'));
    });

    //TODO: Add tests for other pushdata sizes

  });


  group('#buildPublicKeyOut', () {
    test('should create script from public key', () {
      var pubkey = SVPublicKey.fromHex('022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da');
      var lockBuilder = P2PKLockBuilder(pubkey);
      var script = lockBuilder.getScriptPubkey();
      expect(script, isNotNull);
      expect(script.toString(), equals('33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da OP_CHECKSIG'));
    });

    test('', (){
      var coinbaseOutput = "02000000016b748661a108dc35d8868a9a552b9364c6ee3f06a4604f722882d49cdc4d13020000000048473044022073062451397fb5e7e2e02f1603e2a92677d516a5e747b1ae2ad0996387916d4302200ae2ec97d4525621cef07f75f0b92b5e83341761fa604c83daf0390a76d5024241feffffff0200e1f505000000001976a91494837d2d5d6106aa97db38957dcc294181ee91e988ac00021024010000001976a9144d991c88b4fd954ea62aa7182d3b3e251896a83188acd5000000";
      var privateKey = SVPrivateKey.fromWIF("cVVvUsNHhbrgd7aW3gnuGo2qJM45LhHhTCVXrDSJDDcNGE6qmyCs");
      var changeAddress = Address("mu4DpTaD75nheE4z5CQazqm1ivej1vzL4L"); // my address
      var recipientAddress = Address("n3aZKucfWmXeXhX13MREQQnqNfbrWiYKtg"); //bitcoin-cli address

      //Create a Transaction instance from the RAW transaction data create by bitcoin-cli.
      //this transaction contains the UTXO we are interested in
      var txWithUTXO = Transaction.fromHex(coinbaseOutput);

      //Let's create the set of Spending Transaction Inputs. These Transaction Inputs need to refer to the Outputs in
      //the Transaction we are spending from.
      var utxo = txWithUTXO.outputs[0]; //looking at the decoded JSON we can see that our UTXO in at vout[0]
      var pubkey = SVPublicKey.fromHex('022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da');
      var lockBuilder = P2PKLockBuilder(pubkey);

      var locker = P2PKLockBuilder(pubkey);
      var unlocker = P2PKUnlockBuilder();
      var txn = Transaction();
      txn.spendFromOutput(utxo, Transaction.NLOCKTIME_MAX_VALUE, scriptBuilder: unlocker) //set global sequenceNumber/nLocktime time for each Input created
          .spendTo(recipientAddress, BigInt.from(50000000),scriptBuilder: locker) //spend half of a bitcoin (we should have 1 in the UTXO)
          .sendChangeTo(changeAddress,scriptBuilder: locker) // spend change to myself
          .withFeePerKb(100000);

      //Sign the Transaction Input
      txn.signInput(0, privateKey, sighashType: SighashType.SIGHASH_ALL | SighashType.SIGHASH_FORKID);
    });
  });



  group('P2PKH Builder - Locking Script', () {
    test('should create script from livenet address', () {
      var address = Address('1NaTVwXDDUJaXDQajoa9MqHhz4uTxtgK14');
      var lockBulder = P2PKHLockBuilder(address);
      var script = lockBulder.getScriptPubkey();
      expect(script, isNotNull);
      expect( script.toString(), equals( 'OP_DUP OP_HASH160 20 0xecae7d092947b7ee4998e254aa48900d26d2ce1d OP_EQUALVERIFY OP_CHECKSIG'));
      expect(lockBulder.address.toString(), equals('1NaTVwXDDUJaXDQajoa9MqHhz4uTxtgK14'));
    });

    test('should create script from testnet address', () {
      var address = Address('mxRN6AQJaDi5R6KmvMaEmZGe3n5ScV9u33');
      var lockBuilder = P2PKHLockBuilder(address);
      var script = lockBuilder.getScriptPubkey();
      expect(script, isNotNull);
      expect( script.toString(), equals( 'OP_DUP OP_HASH160 20 0xb96b816f378babb1fe585b7be7a2cd16eb99b3e4 OP_EQUALVERIFY OP_CHECKSIG'));
      expect(lockBuilder.address.toString(), equals('mxRN6AQJaDi5R6KmvMaEmZGe3n5ScV9u33'));
    });

    test('should create script from public key', () {
      var pubkey = SVPublicKey.fromHex( '022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da');
      var lockBuilder = P2PKHLockBuilder.fromPublicKey(pubkey, networkType: NetworkType.TEST);
      var script = lockBuilder.getScriptPubkey();
      expect(script, isNotNull);
      expect( script.toString(), equals('OP_DUP OP_HASH160 20 0x9674af7395592ec5d91573aa8d6557de55f60147 OP_EQUALVERIFY OP_CHECKSIG'));
      expect(lockBuilder.address.networkType, equals(NetworkType.TEST));
    });
  });

  group ('P2PKH Builder - Unlocking Script deserialize', () {
    test('should identify this known unlocking script (uncompressed pubkey version)', () {
      var pubkey = SVPublicKey.fromHex("04e365859b3c78a8b7c202412b949ebca58e147dba297be29eee53cd3e1d300a6419bc780cc9aec0dc94ed194e91c8f6433f1b781ee00eac0ead2aae1e8e0712c6");
      var signature = SVSignature.fromTxFormat("3046022100bb3c194a30e460d81d34be0a230179c043a656f67e3c5c8bf47eceae7c4042ee0221008bf54ca11b2985285be0fd7a212873d243e6e73f5fad57e8eb14c4f39728b8c601");
      var script = SVScript.fromString('73 0x3046022100bb3c194a30e460d81d34be0a230179c043a656f67e3c5c8bf47eceae7c4042ee0221008bf54ca11b2985285be0fd7a212873d243e6e73f5fad57e8eb14c4f39728b8c601 65 0x04e365859b3c78a8b7c202412b949ebca58e147dba297be29eee53cd3e1d300a6419bc780cc9aec0dc94ed194e91c8f6433f1b781ee00eac0ead2aae1e8e0712c6');

      var unlockBuilder = P2PKHUnlockBuilder(pubkey);
      unlockBuilder.fromScript(script);

      expect(unlockBuilder.signatures, isNotEmpty);
      expect(unlockBuilder.signerPubkey, isNotNull);
      expect(unlockBuilder.signerPubkey.toString(), equals(pubkey.toString()));
      expect(unlockBuilder.signatures[0].toString(), equals(signature.toString()));

    });

  });


  group('P2SH builder', (){

    test('should create scriptPubkey from hash', () {
      var inner = SVScript.fromString('OP_DUP OP_HASH160 20 0x06c06f6d931d7bfba2b5bd5ad0d19a8f257af3e3 OP_EQUALVERIFY OP_CHECKSIG');
      var scriptHash = hash160(HEX.decode(inner.toHex()));
      var lockBuilder = P2SHLockBuilder(HEX.encode(scriptHash));
      var script = lockBuilder.getScriptPubkey();
      expect(script, isNotNull);
      expect(script.toString(), equals('OP_HASH160 20 0x45ea3f9133e7b1cef30ba606f8433f993e41e159 OP_EQUAL'));
    });

    test('should create scriptPubkey from another script', () {
      var inner = SVScript.fromString('OP_DUP OP_HASH160 20 0x06c06f6d931d7bfba2b5bd5ad0d19a8f257af3e3 OP_EQUALVERIFY OP_CHECKSIG');
      var lockBuilder = P2SHLockBuilder(null);
      lockBuilder.fromScript(inner);
      var script = lockBuilder.getScriptPubkey();
      expect(script, isNotNull);
      expect(script.toString(), equals('OP_HASH160 20 0x45ea3f9133e7b1cef30ba606f8433f993e41e159 OP_EQUAL'));
    });
  });




  var pubKeyHexes = [
    '022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da',
    '03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9',
    '021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18',
    '02bf97f572a02a8900246d72c2e8fa3d3798a6e59c4e17de2d131d9c60d0d9b574',
    '036a98a36aa7665874b1ba9130bc6d318e52fd3bdb5969532d7fc09bf2476ff842',
    '033aafcbead78c08b0e0aacc1b0cdb40702a7c709b660bebd286e973242127e15b'
  ];

  var sortkeys = pubKeyHexes.getRange(0, 3).map((key) => SVPublicKey.fromHex(key));

  group('P2MS (multisig) - Locking Script', (){
    test('should create sorted script by default', () {
      //var s = Script.buildMultisigOut(sortkeys, 2);
      var lockBuilder = P2MSLockBuilder(sortkeys.toList(), 2);
      var script = lockBuilder.getScriptPubkey();
      expect( script.toString(), equals( 'OP_2 33 0x021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18 33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da 33 0x03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9 OP_3 OP_CHECKMULTISIG'));
    });

    test( 'should fail when number of required signatures is greater than number of pubkeys', () {
      expect(sortkeys.length, equals(3));
      var lockBuilder = P2MSLockBuilder(sortkeys.toList(), 4);
      expect(() => lockBuilder.getScriptPubkey(), throwsException);
    });

    test('should create unsorted script if specified', () {
      var lockBuilder = P2MSLockBuilder(sortkeys.toList(), 2);
      var unsortedLockBuilder = P2MSLockBuilder(sortkeys.toList(), 2, sorting: false);
      var sortedScript = lockBuilder.getScriptPubkey();
      var unsortedScript = unsortedLockBuilder.getScriptPubkey();

      expect(sortedScript.toString(), isNot(equals(unsortedScript.toString())));
      expect(unsortedScript.toString(), equals( 'OP_2 33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da 33 0x03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9 33 0x021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18 OP_3 OP_CHECKMULTISIG'));
    });

    test('can recover state using fromScript', (){
      var script = SVScript.fromString('OP_2 33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da 33 0x03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9 OP_2 OP_CHECKMULTISIG');

      var lockBuilder = P2MSLockBuilder(null, null);
      lockBuilder.fromScript(script);

      expect(lockBuilder.publicKeys?.length, equals(2));
      expect(lockBuilder.requiredSigs, equals(2));
      expect(lockBuilder.publicKeys[0].toHex(), equals('022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da'));
      expect(lockBuilder.publicKeys[1].toHex(), equals('03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9'));
    });
  });


  group('P2MS (multisig) - unlocking Script', () {
    Address fromAddress = Address('mszYqVnqKoQx4jcTdJXxwKAissE3Jbrrc1');
    Address toAddress = Address('mrU9pEmAx26HcbKVrABvgL7AwA5fjNFoDc');
    Address changeAddress = Address('mgBCJAsvzgT2qNNeXsoECg2uPKrUsZ76up');

    var private1 = SVPrivateKey.fromWIF( 'cSBnVM4xvxarwGQuAfQFwqDg9k5tErHUHzgWsEfD4zdwUasvqRVY');
    var private2 = SVPrivateKey.fromWIF( "cVVvUsNHhbrgd7aW3gnuGo2qJM45LhHhTCVXrDSJDDcNGE6qmyCs");
    var public1 = private1.publicKey;
    var public2 = private2.publicKey;

    var lockBuilder = P2MSLockBuilder([public1, public2], 2);

    var simpleUtxoWith100000Satoshis = {
      "address": fromAddress,
      "txId": 'a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458',
      "outputIndex": 0,
      "scriptPubKey": lockBuilder.getScriptPubkey().toString(),
      "satoshis": BigInt.from(100000)
    };

    test('can perform a multisig spend', () {
      var unlockBuilder = P2MSUnlockBuilder();
      var transaction = new Transaction()
          .spendFromMap(simpleUtxoWith100000Satoshis, scriptBuilder: unlockBuilder)
          .spendTo(toAddress, BigInt.from(500000), scriptBuilder: P2PKHLockBuilder(toAddress))
          .sendChangeTo(changeAddress, scriptBuilder: P2PKHLockBuilder(changeAddress));

      transaction.withFeePerKb(100000);

      transaction.signInput(0, private1);
      transaction.signInput(0, private2);

      expect(unlockBuilder.signatures.length, equals(2));
      expect(unlockBuilder.getScriptSig().toString(), equals('OP_0 71 0x30440220506a721a4aca80943146700333be6f5f0abd96798b4b5e21d14a45f6f3e1c96d022074be7308c17a86d327ad6f9b59116f45edff218187e5a6bcff6c58150ec94f9700 71 0x304402205133d18807f1261bd0712a6d334cf85a286fe3aaec08efbce824a31efe60c0a9022048d52308728a602a046adceb990188062955a0f20f390895066325406b41644700'));

      //Interpreter().verifyScript(scriptSig, scriptPubkey) FIXME: for another day
    });

    test('can reconstruct P2MS unlocking script', (){

      var script = SVScript.fromString('OP_0 0x47 0x3044022002a27769ee33db258bdf7a3792e7da4143ec4001b551f73e6a190b8d1bde449d02206742c56ccd94a7a2e16ca52fc1ae4a0aa122b0014a867a80de104f9cb18e472c01 0x48 0x30450220357011fd3b3ad2b8f2f2d01e05dc6108b51d2a245b4ef40c112d6004596f0475022100a8208c93a39e0c366b983f9a80bfaf89237fcd64ca543568badd2d18ee2e1d7501');
      var unlockBuilder = P2MSUnlockBuilder();
      unlockBuilder.fromScript(script);

      expect(unlockBuilder.signatures.length, equals(2));
      expect(unlockBuilder.signatures[0].toTxFormat(), equals('3044022002a27769ee33db258bdf7a3792e7da4143ec4001b551f73e6a190b8d1bde449d02206742c56ccd94a7a2e16ca52fc1ae4a0aa122b0014a867a80de104f9cb18e472c01'));
      expect(unlockBuilder.signatures[1].toTxFormat(), equals('30450220357011fd3b3ad2b8f2f2d01e05dc6108b51d2a245b4ef40c112d6004596f0475022100a8208c93a39e0c366b983f9a80bfaf89237fcd64ca543568badd2d18ee2e1d7501'));

    });
  });

     */
}
