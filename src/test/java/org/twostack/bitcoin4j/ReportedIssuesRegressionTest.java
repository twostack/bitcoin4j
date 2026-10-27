package org.twostack.bitcoin4j;

import org.junit.Test;
import org.twostack.bitcoin4j.block.Block;
import org.twostack.bitcoin4j.crypto.HDPath;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.bitcoin4j.script.Interpreter;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptBuilder;
import org.twostack.bitcoin4j.script.ScriptChunk;
import org.twostack.bitcoin4j.script.ScriptOpCodes;
import org.twostack.bitcoin4j.transaction.*;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;

import static org.junit.Assert.*;

/**
 * Regression tests for issues reported against 1.7.0. This lives outside the transaction package
 * on purpose, so that it only uses the public API.
 */
public class ReportedIssuesRegressionTest {

    private static final int SIGHASH_ALL_FORKID = SigHashType.ALL.value | SigHashType.FORKID.value;
    private static final BigInteger FUNDING_AMOUNT = BigInteger.valueOf(100000);

    private final PrivateKey key = new PrivateKey();
    private final Address address = Address.fromKey(NetworkAddressType.TEST_PKH, key.getPublicKey());

    /** A transaction with a single output locked by the given script. */
    private static Transaction fundingTx(Script lockingScript, BigInteger amount) {
        Transaction tx = new Transaction();
        tx.addInput(new TransactionInput(new byte[32], 0, TransactionInput.MAX_SEQ_NUMBER, new DefaultUnlockBuilder()));
        tx.addOutput(new TransactionOutput(amount, lockingScript));
        return tx;
    }

    private static void assertSpends(Transaction spendingTx, int inputIndex, TransactionOutput utxo, Set<Script.VerifyFlag> flags) {
        new Interpreter().correctlySpends(
                spendingTx.getInputs().get(inputIndex).getScriptSig(),
                utxo.getScript(),
                spendingTx,
                inputIndex,
                flags,
                Coin.valueOf(utxo.getAmount().longValue()));
    }

    private static void assertSpends(Transaction spendingTx, int inputIndex, TransactionOutput utxo) {
        assertSpends(spendingTx, inputIndex, utxo, EnumSet.of(Script.VerifyFlag.SIGHASH_FORKID));
    }

    // 1 + 8: multisig spend verifies; lock builder doesn't sort (or choke on) the caller's immutable list
    @Test
    public void multisigSpendVerifies() throws Exception {
        List<PrivateKey> keys = Arrays.asList(new PrivateKey(), new PrivateKey(), new PrivateKey());
        List<PublicKey> pubKeys = Collections.unmodifiableList(Arrays.asList(
                keys.get(0).getPublicKey(), keys.get(1).getPublicKey(), keys.get(2).getPublicKey()));

        P2MSLockBuilder locker = new P2MSLockBuilder(pubKeys, 2);
        Transaction funding = fundingTx(locker.getLockingScript(), FUNDING_AMOUNT);
        TransactionOutput utxo = funding.getOutputs().get(0);

        Transaction tx = new TransactionBuilder()
                .spendFromTransaction(funding, 0, TransactionInput.MAX_SEQ_NUMBER, new P2MSUnlockBuilder())
                .spendTo(new P2PKHLockBuilder(address), BigInteger.valueOf(90000))
                .build(false);

        //signatures must appear in the same order as their public keys in the locking script
        List<PublicKey> scriptOrder = locker.getPublicKeys();
        int signed = 0;
        for (PublicKey pub : scriptOrder) {
            for (PrivateKey k : keys) {
                if (signed < 2 && k.getPublicKey().getPubKeyHex().equals(pub.getPubKeyHex())) {
                    new TransactionSigner(SIGHASH_ALL_FORKID, k).sign(tx, utxo, 0);
                    signed++;
                }
            }
        }

        assertSpends(tx, 0, utxo, EnumSet.of(Script.VerifyFlag.SIGHASH_FORKID, Script.VerifyFlag.NULLDUMMY));
    }

    // 2: uncompressed WIF round-trips and gives the uncompressed public key (and therefore Address)
    @Test
    public void uncompressedWifGivesUncompressedAddress() throws Exception {
        //https://en.bitcoin.it/wiki/Wallet_import_format
        String wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        byte[] privBytes = Utils.HEX.decode("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d");

        PrivateKey uncompressed = PrivateKey.fromWIF(wif);
        assertFalse(uncompressed.isCompressed());
        assertEquals(wif, uncompressed.toWIF());

        byte[] expectedPub = ECKey.fromPrivate(privBytes, false).getPubKey();
        assertEquals(65, expectedPub.length);
        assertArrayEquals(expectedPub, uncompressed.getPublicKey().getPubKeyBytes());

        Address expected = Address.fromKey(NetworkAddressType.MAIN_PKH, PublicKey.fromBytes(expectedPub));
        assertEquals(expected.toString(), Address.fromKey(NetworkAddressType.MAIN_PKH, uncompressed.getPublicKey()).toString());

        //the compressed encoding of the same key still behaves as before
        PrivateKey compressed = new PrivateKey(ECKey.fromPrivate(privBytes, true), true, org.twostack.bitcoin4j.params.NetworkType.MAIN);
        assertTrue(compressed.isCompressed());
        assertEquals(compressed.toWIF(), PrivateKey.fromWIF(compressed.toWIF()).toWIF());
        assertEquals(33, PrivateKey.fromWIF(compressed.toWIF()).getPublicKey().getPubKeyBytes().length);
    }

    // 3 + 11: spendFromOutput / spendFromOutpoint with a signer produce valid signatures, from outside the package
    @Test
    public void spendFromOutputAndOutpointWithSignerVerify() throws Exception {
        Transaction funding = fundingTx(new P2PKHLockBuilder(address).getLockingScript(), FUNDING_AMOUNT);
        TransactionOutput utxo = funding.getOutputs().get(0);

        Transaction tx = new TransactionBuilder()
                .spendFromOutput(new TransactionSigner(SIGHASH_ALL_FORKID, key), funding.getTransactionId(), 0,
                        utxo.getAmount(), utxo.getScript(), TransactionInput.MAX_SEQ_NUMBER, new P2PKHUnlockBuilder(key.getPublicKey()))
                .spendTo(new P2PKHLockBuilder(address), BigInteger.valueOf(90000))
                .sendChangeTo(address)
                .build(true);
        assertSpends(tx, 0, utxo);

        TransactionOutpoint outpoint = new TransactionOutpoint(funding.getTransactionId(), 0, utxo.getAmount(), utxo.getScript());
        Transaction tx2 = new TransactionBuilder()
                .spendFromOutpoint(new TransactionSigner(SIGHASH_ALL_FORKID, key), outpoint, TransactionInput.MAX_SEQ_NUMBER, new P2PKHUnlockBuilder(key.getPublicKey()))
                .spendTo(new P2PKHLockBuilder(address), BigInteger.valueOf(90000))
                .sendChangeTo(address)
                .build(true);
        assertSpends(tx2, 0, utxo);
    }

    // 4: CHRONICLE signatures verify
    @Test
    public void chronicleSignatureVerifies() throws Exception {
        Transaction funding = fundingTx(new P2PKHLockBuilder(address).getLockingScript(), FUNDING_AMOUNT);
        TransactionOutput utxo = funding.getOutputs().get(0);

        int sigHashType = SIGHASH_ALL_FORKID | SigHashType.CHRONICLE.value;
        Transaction tx = new TransactionBuilder()
                .spendFromTransaction(new TransactionSigner(sigHashType, key), funding, 0, TransactionInput.MAX_SEQ_NUMBER, new P2PKHUnlockBuilder(key.getPublicKey()))
                .spendTo(new P2PKHLockBuilder(address), BigInteger.valueOf(90000))
                .sendChangeTo(address)
                .build(true);

        assertSpends(tx, 0, utxo, EnumSet.of(Script.VerifyFlag.SIGHASH_FORKID, Script.VerifyFlag.AFTER_CHRONICLE));
    }

    // 5: one-byte pushes of 1..16 serialise (as OP_1..OP_16), including via the data-output builders
    @Test
    public void smallOneBytePushesSerialise() throws Exception {
        for (int i = 1; i <= 16; i++) {
            Script script = new ScriptBuilder().data(new byte[]{(byte) i}).build();
            assertArrayEquals(new byte[]{(byte) Script.encodeToOpN(i)}, script.getProgram());
        }

        Script data = new UnspendableDataLockBuilder(Collections.singletonList(ByteBuffer.wrap(new byte[]{5}))).getLockingScript();
        assertTrue(data.getProgram().length > 0);
        assertEquals(1, ((org.twostack.bitcoin4j.script.OpReturnScriptInfo)
                org.twostack.bitcoin4j.script.ScriptTemplateRegistry.getInstance().extractScriptInfo(data)).getDataChunks().size());

        Script p2pkhData = new P2PKHDataLockBuilder(address, ByteBuffer.wrap(new byte[]{7})).getLockingScript();
        assertTrue(p2pkhData.getProgram().length > 0);
    }

    // 6
    @Test
    public void isFinalReflectsSequenceNumber() {
        assertTrue(new TransactionInput(new byte[32], 0, TransactionInput.MAX_SEQ_NUMBER, new DefaultUnlockBuilder()).isFinal());
        assertFalse(new TransactionInput(new byte[32], 0, TransactionInput.MAX_SEQ_NUMBER - 1, new DefaultUnlockBuilder()).isFinal());
    }

    // 7: P2PK unlocker with a null signature gets filled in by the signer
    @Test
    public void p2pkUnlockWithNullSignatureIsSignedByBuilder() throws Exception {
        Transaction funding = fundingTx(new P2PKLockBuilder(key.getPublicKey()).getLockingScript(), FUNDING_AMOUNT);
        TransactionOutput utxo = funding.getOutputs().get(0);

        Transaction tx = new TransactionBuilder()
                .spendFromTransaction(new TransactionSigner(SIGHASH_ALL_FORKID, key), funding, 0, TransactionInput.MAX_SEQ_NUMBER, new P2PKUnlockBuilder((TransactionSignature) null))
                .spendTo(new P2PKHLockBuilder(address), BigInteger.valueOf(90000))
                .sendChangeTo(address)
                .build(true);

        assertSpends(tx, 0, utxo);
    }

    // 9 + 10: change goes last, and reflects outputs added after sendChangeTo()
    @Test
    public void changeOutputIsLastAndRecalculated() throws Exception {
        Transaction funding = fundingTx(new P2PKHLockBuilder(address).getLockingScript(), FUNDING_AMOUNT);

        TransactionBuilder builder = new TransactionBuilder()
                .spendFromTransaction(new TransactionSigner(SIGHASH_ALL_FORKID, key), funding, 0, TransactionInput.MAX_SEQ_NUMBER, new P2PKHUnlockBuilder(key.getPublicKey()))
                .sendChangeTo(address)
                .spendTo(new P2PKHLockBuilder(address), BigInteger.valueOf(30000))
                .spendTo(new P2PKHLockBuilder(address), BigInteger.valueOf(20000));
        Transaction tx = builder.build(true);

        List<TransactionOutput> outputs = tx.getOutputs();
        assertEquals(3, outputs.size());
        assertEquals(BigInteger.valueOf(30000), outputs.get(0).getAmount());
        assertEquals(BigInteger.valueOf(20000), outputs.get(1).getAmount());

        BigInteger fee = builder.getFee();
        assertEquals(FUNDING_AMOUNT.subtract(BigInteger.valueOf(50000)).subtract(fee), outputs.get(2).getAmount());
    }

    // 12
    @Test
    public void hdPathAcceptsApostrophe() {
        HDPath apostrophe = HDPath.parsePath("m/44'/0'/0'/0/1");
        assertEquals(HDPath.parsePath("m/44H/0H/0H/0/1"), apostrophe);
        assertTrue(apostrophe.get(0).isHardened());
        assertFalse(apostrophe.get(3).isHardened());
    }

    // 13: zero-satoshi OP_RETURN outputs pass the dust check
    @Test
    public void zeroValueOpReturnPassesChecks() throws Exception {
        Transaction funding = fundingTx(new P2PKHLockBuilder(address).getLockingScript(), FUNDING_AMOUNT);

        Transaction tx = new TransactionBuilder()
                .spendFromTransaction(new TransactionSigner(SIGHASH_ALL_FORKID, key), funding, 0, TransactionInput.MAX_SEQ_NUMBER, new P2PKHUnlockBuilder(key.getPublicKey()))
                .spendTo(new UnspendableDataLockBuilder(Collections.singletonList(ByteBuffer.wrap("hello".getBytes()))), BigInteger.ZERO)
                .sendChangeTo(address)
                .build(true);

        assertEquals(2, tx.getOutputs().size());
    }

    // 14: the size estimate accounts for multisig unlocking scripts
    @Test
    public void feeEstimateAccountsForMultisigInputs() throws Exception {
        List<PublicKey> pubKeys = new ArrayList<>();
        for (int i = 0; i < 15; i++) pubKeys.add(new PrivateKey().getPublicKey());
        Script multisig = new P2MSLockBuilder(pubKeys, 15).getLockingScript();
        Transaction funding = fundingTx(multisig, FUNDING_AMOUNT);
        Transaction p2pkhFunding = fundingTx(new P2PKHLockBuilder(address).getLockingScript(), FUNDING_AMOUNT);

        TransactionBuilder msBuilder = new TransactionBuilder()
                .spendFromTransaction(new TransactionSigner(SIGHASH_ALL_FORKID, key), funding, 0, TransactionInput.MAX_SEQ_NUMBER, new P2MSUnlockBuilder());
        TransactionBuilder pkhBuilder = new TransactionBuilder()
                .spendFromTransaction(new TransactionSigner(SIGHASH_ALL_FORKID, key), p2pkhFunding, 0, TransactionInput.MAX_SEQ_NUMBER, new P2PKHUnlockBuilder(key.getPublicKey()));

        //OP_0 plus 15 signature pushes of up to 74 bytes each
        assertTrue(msBuilder.estimateSize() - pkhBuilder.estimateSize() > 15 * 70 - 149);
    }

    // 16
    @Test
    public void blockExposesHeaderFields() {
        Sha256Hash merkle = Sha256Hash.wrap("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
        Block genesis = new Block(1, Sha256Hash.ZERO_HASH, merkle, 1231006505L, 0x1d00ffffL, 2083236893L, Collections.emptyList());

        assertEquals(1, genesis.getVersion());
        assertEquals(Sha256Hash.ZERO_HASH, genesis.getPrevBlockHash());
        assertEquals(1231006505L, genesis.getTime());
        assertEquals(0x1d00ffffL, genesis.getDifficultyTarget());
        assertEquals(2083236893L, genesis.getNonce());
    }

    // lock time is honoured: final inputs are made non-final when a lock time is set
    @Test
    public void lockTimeMakesInputsNonFinal() throws Exception {
        Transaction funding = fundingTx(new P2PKHLockBuilder(address).getLockingScript(), FUNDING_AMOUNT);
        TransactionOutput utxo = funding.getOutputs().get(0);

        Transaction tx = new TransactionBuilder()
                .spendFromTransaction(new TransactionSigner(SIGHASH_ALL_FORKID, key), funding, 0, TransactionInput.MAX_SEQ_NUMBER, new P2PKHUnlockBuilder(key.getPublicKey()))
                .spendTo(new P2PKHLockBuilder(address), BigInteger.valueOf(90000))
                .sendChangeTo(address)
                .lockUntilBlockHeight(800000)
                .build(true);

        assertEquals(800000, tx.getLockTime());
        assertFalse(tx.getInputs().get(0).isFinal());
        assertSpends(tx, 0, utxo);
    }

    // dartsv 3.1.1 parity: after Chronicle, a CHECKSIG in the unlocking script signs the
    // unlocking script tail followed by the whole locking script
    @Test
    public void chronicleScriptCodeForChecksigInUnlockingScript() throws Exception {
        Script lockingScript = new ScriptBuilder().op(ScriptOpCodes.OP_VERIFY).op(ScriptOpCodes.OP_1).build();
        Transaction funding = fundingTx(lockingScript, FUNDING_AMOUNT);
        TransactionOutput utxo = funding.getOutputs().get(0);

        Transaction tx = new TransactionBuilder()
                .spendFromTransaction(funding, 0, TransactionInput.MAX_SEQ_NUMBER, new DefaultUnlockBuilder())
                .spendTo(new P2PKHLockBuilder(address), BigInteger.valueOf(90000))
                .build(false);

        //scriptCode = (unlocking script with the signature removed) + locking script
        byte[] pub = key.getPublicKey().getPubKeyBytes();
        Script scriptCode = new ScriptBuilder().data(pub).op(ScriptOpCodes.OP_CHECKSIG)
                .op(ScriptOpCodes.OP_VERIFY).op(ScriptOpCodes.OP_1).build();
        byte[] hash = new SigHash().createHash(tx, SIGHASH_ALL_FORKID, 0, scriptCode, utxo.getAmount());
        ECKey.ECDSASignature ecSig = ECKey.ECDSASignature.decodeFromDER(key.sign(hash));
        byte[] sig = new TransactionSignature(ecSig.r, ecSig.s, SIGHASH_ALL_FORKID).toTxFormat();

        tx.getInputs().get(0).setScript(new ScriptBuilder().data(sig).data(pub).op(ScriptOpCodes.OP_CHECKSIG).build());

        assertSpends(tx, 0, utxo, EnumSet.of(Script.VerifyFlag.SIGHASH_FORKID, Script.VerifyFlag.AFTER_CHRONICLE));

        //before Chronicle the scriptCode is only the unlocking script tail, so this signature doesn't verify
        try {
            assertSpends(tx, 0, utxo, EnumSet.of(Script.VerifyFlag.SIGHASH_FORKID));
            fail("expected pre-Chronicle verification to fail");
        } catch (org.twostack.bitcoin4j.script.ScriptException expected) {
        }
    }

    @Test
    public void lockTimeArgumentsAreValidated() {
        TransactionBuilder builder = new TransactionBuilder();
        builder.lockUntilBlockHeight(0);
        builder.lockUntilBlockHeight(Transaction.LOCKTIME_THRESHOLD - 1);
        builder.lockUntilUnixTime(Transaction.LOCKTIME_THRESHOLD);

        for (Runnable r : Arrays.<Runnable>asList(
                () -> builder.lockUntilBlockHeight(-1),
                () -> builder.lockUntilBlockHeight(Transaction.LOCKTIME_THRESHOLD),
                () -> builder.lockUntilUnixTime(Transaction.LOCKTIME_THRESHOLD - 1),
                () -> builder.lockUntilUnixTime(Transaction.NLOCKTIME_MAX_VALUE + 1))) {
            try {
                r.run();
                fail("expected IllegalArgumentException");
            } catch (IllegalArgumentException expected) {
            }
        }
    }
}
