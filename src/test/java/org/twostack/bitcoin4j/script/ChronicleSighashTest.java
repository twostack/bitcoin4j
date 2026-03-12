package org.twostack.bitcoin4j.script;

import org.junit.Test;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.transaction.SigHash;
import org.twostack.bitcoin4j.transaction.SigHashType;
import org.twostack.bitcoin4j.transaction.Transaction;
import org.twostack.bitcoin4j.transaction.TransactionSignature;

import java.math.BigInteger;

import static org.junit.Assert.*;

public class ChronicleSighashTest {

    @Test
    public void sighashTypeRecognizesChronicle() {
        assertTrue(SigHashType.hasValue(SigHashType.CHRONICLE.value | SigHashType.ALL.value)); // 0x21
        assertTrue(SigHashType.hasValue(SigHashType.CHRONICLE.value | SigHashType.NONE.value)); // 0x22
        assertTrue(SigHashType.hasValue(SigHashType.CHRONICLE.value | SigHashType.SINGLE.value)); // 0x23
    }

    @Test
    public void sighashTypeRecognizesChronicleWithForkId() {
        assertTrue(SigHashType.hasValue(0x61)); // ALL | CHRONICLE | FORKID
        assertTrue(SigHashType.hasValue(0x62)); // NONE | CHRONICLE | FORKID
        assertTrue(SigHashType.hasValue(0x63)); // SINGLE | CHRONICLE | FORKID
    }

    @Test
    public void sighashTypeRecognizesChronicleWithAnyoneCanPay() {
        assertTrue(SigHashType.hasValue(0xE1)); // ALL | CHRONICLE | FORKID | ANYONECANPAY
    }

    @Test
    public void sighashTypeRejectsInvalidBaseType() {
        assertFalse(SigHashType.hasValue(0x24)); // invalid base type 4 | CHRONICLE
    }

    @Test
    public void hasChronicleDetectsChronicleFlag() {
        byte[] sigWithChronicle = new byte[]{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x61}; // sighash 0x61
        assertTrue(TransactionSignature.hasChronicle(sigWithChronicle));
    }

    @Test
    public void hasChronicleReturnsFalseWithoutFlag() {
        byte[] sigWithoutChronicle = new byte[]{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x41}; // sighash 0x41
        assertFalse(TransactionSignature.hasChronicle(sigWithoutChronicle));
    }

    @Test
    public void hasChronicleReturnsFalseForEmpty() {
        assertFalse(TransactionSignature.hasChronicle(new byte[0]));
    }

    @Test
    public void calcSigHashValueWithChronicle() {
        int value = TransactionSignature.calcSigHashValue(SigHashType.ALL, false, true, true);
        assertEquals(0x61, value); // ALL(1) | FORKID(0x40) | CHRONICLE(0x20)
    }

    @Test
    public void calcSigHashValueChronicleWithoutForkId() {
        int value = TransactionSignature.calcSigHashValue(SigHashType.ALL, false, false, true);
        assertEquals(0x21, value); // ALL(1) | CHRONICLE(0x20)
    }

    @Test
    public void existingSighashTypesStillWork() {
        // Ensure backward compatibility
        assertTrue(SigHashType.hasValue(SigHashType.ALL.value)); // 1
        assertTrue(SigHashType.hasValue(SigHashType.NONE.value)); // 2
        assertTrue(SigHashType.hasValue(SigHashType.SINGLE.value)); // 3
        assertTrue(SigHashType.hasValue(SigHashType.ALL.value | SigHashType.FORKID.value)); // 0x41
        assertTrue(SigHashType.hasValue(SigHashType.ALL.value | SigHashType.ANYONECANPAY.value)); // 0x81
        assertTrue(SigHashType.hasValue(SigHashType.ALL.value | SigHashType.FORKID.value | SigHashType.ANYONECANPAY.value)); // 0xC1
    }

    @Test
    public void chronicleSighashUsesLegacyPathEvenWithForkId() throws Exception {
        // When CHRONICLE bit is set, createHash should use legacy/OTDA path
        // even when FORKID is also present
        Transaction tx = new Transaction();
        tx.setVersion(2);
        tx.addInput(new org.twostack.bitcoin4j.transaction.TransactionInput(
                new byte[32], 0, 0xFFFFFFFFL,
                new org.twostack.bitcoin4j.transaction.DefaultUnlockBuilder(
                        new ScriptBuilder().op(ScriptOpCodes.OP_1).build()
                )
        ));
        tx.addOutput(new org.twostack.bitcoin4j.transaction.TransactionOutput(
                BigInteger.valueOf(50000),
                new ScriptBuilder().op(ScriptOpCodes.OP_DUP).op(ScriptOpCodes.OP_HASH160)
                        .data(new byte[20]).op(ScriptOpCodes.OP_EQUALVERIFY)
                        .op(ScriptOpCodes.OP_CHECKSIG).build()
        ));

        Script subscript = new ScriptBuilder()
                .op(ScriptOpCodes.OP_DUP).op(ScriptOpCodes.OP_HASH160)
                .data(new byte[20]).op(ScriptOpCodes.OP_EQUALVERIFY)
                .op(ScriptOpCodes.OP_CHECKSIG).build();

        SigHash sigHash = new SigHash();

        // SIGHASH_ALL | FORKID | CHRONICLE = 0x61
        int chronicleForkidType = SigHashType.ALL.value | SigHashType.FORKID.value | SigHashType.CHRONICLE.value;

        // With afterChronicle=true, should use legacy path (different hash than ForkID path)
        byte[] chronicleHash = sigHash.createHash(tx, chronicleForkidType, 0, subscript, BigInteger.valueOf(50000), null, true);

        // With afterChronicle=false, same sighash type should use ForkID path
        byte[] forkidHash = sigHash.createHash(tx, chronicleForkidType, 0, subscript, BigInteger.valueOf(50000), null, false);

        // The two hashes must differ since they use different digest algorithms
        assertFalse("Chronicle should use legacy path, producing different hash than ForkID path",
                java.util.Arrays.equals(chronicleHash, forkidHash));
    }

    @Test
    public void chronicleSighashUsesLockingScriptAsScriptCode() throws Exception {
        // When CHRONICLE is active and lockingScript is provided, it should be used as scriptCode
        Transaction tx = new Transaction();
        tx.setVersion(2);
        tx.addInput(new org.twostack.bitcoin4j.transaction.TransactionInput(
                new byte[32], 0, 0xFFFFFFFFL,
                new org.twostack.bitcoin4j.transaction.DefaultUnlockBuilder(
                        new ScriptBuilder().op(ScriptOpCodes.OP_1).build()
                )
        ));
        tx.addOutput(new org.twostack.bitcoin4j.transaction.TransactionOutput(
                BigInteger.valueOf(50000),
                new ScriptBuilder().op(ScriptOpCodes.OP_1).build()
        ));

        Script subscript = new ScriptBuilder().op(ScriptOpCodes.OP_1).build();
        Script lockingScript = new ScriptBuilder()
                .op(ScriptOpCodes.OP_DUP).op(ScriptOpCodes.OP_HASH160)
                .data(new byte[20]).op(ScriptOpCodes.OP_EQUALVERIFY)
                .op(ScriptOpCodes.OP_CHECKSIG).build();

        SigHash sigHash = new SigHash();

        // SIGHASH_ALL | CHRONICLE = 0x21 (no FORKID, legacy path)
        int chronicleType = SigHashType.ALL.value | SigHashType.CHRONICLE.value;

        byte[] hashWithLocking = sigHash.createHash(tx, chronicleType, 0, subscript, BigInteger.valueOf(50000), lockingScript, true);
        byte[] hashWithoutLocking = sigHash.createHash(tx, chronicleType, 0, subscript, BigInteger.valueOf(50000), null, true);

        // The hashes should differ because lockingScript overrides subscript as scriptCode
        assertFalse("lockingScript should change the hash when CHRONICLE is active",
                java.util.Arrays.equals(hashWithLocking, hashWithoutLocking));
    }

    @Test
    public void chroniclePreimageUsesLegacyPath() throws Exception {
        // Verify getSighashPreimage also routes to legacy path for CHRONICLE
        Transaction tx = new Transaction();
        tx.setVersion(2);
        tx.addInput(new org.twostack.bitcoin4j.transaction.TransactionInput(
                new byte[32], 0, 0xFFFFFFFFL,
                new org.twostack.bitcoin4j.transaction.DefaultUnlockBuilder(
                        new ScriptBuilder().op(ScriptOpCodes.OP_1).build()
                )
        ));
        tx.addOutput(new org.twostack.bitcoin4j.transaction.TransactionOutput(
                BigInteger.valueOf(50000),
                new ScriptBuilder().op(ScriptOpCodes.OP_1).build()
        ));

        Script subscript = new ScriptBuilder().op(ScriptOpCodes.OP_1).build();

        SigHash sigHash = new SigHash();

        // SIGHASH_ALL | FORKID | CHRONICLE = 0x61
        int chronicleForkidType = SigHashType.ALL.value | SigHashType.FORKID.value | SigHashType.CHRONICLE.value;

        byte[] chroniclePreimage = sigHash.getSighashPreimage(tx, chronicleForkidType, 0, subscript, BigInteger.valueOf(50000), null, true);
        byte[] forkidPreimage = sigHash.getSighashPreimage(tx, chronicleForkidType, 0, subscript, BigInteger.valueOf(50000), null, false);

        // Preimages should differ — different digest structure
        assertFalse("Chronicle preimage should differ from ForkID preimage",
                java.util.Arrays.equals(chroniclePreimage, forkidPreimage));
    }

    @Test
    public void nonChronicleSighashUnaffectedByBit0x20() throws Exception {
        // When afterChronicle=false, bit 0x20 in sighash type should not affect routing
        Transaction tx = new Transaction();
        tx.setVersion(1);
        tx.addInput(new org.twostack.bitcoin4j.transaction.TransactionInput(
                new byte[32], 0, 0xFFFFFFFFL,
                new org.twostack.bitcoin4j.transaction.DefaultUnlockBuilder(
                        new ScriptBuilder().op(ScriptOpCodes.OP_1).build()
                )
        ));
        tx.addOutput(new org.twostack.bitcoin4j.transaction.TransactionOutput(
                BigInteger.valueOf(50000),
                new ScriptBuilder().op(ScriptOpCodes.OP_1).build()
        ));

        Script subscript = new ScriptBuilder().op(ScriptOpCodes.OP_1).build();

        SigHash sigHash = new SigHash();

        // SIGHASH_ALL | FORKID | 0x20 = 0x61 — but afterChronicle=false
        int typeWith0x20 = SigHashType.ALL.value | SigHashType.FORKID.value | 0x20;

        // Both should use ForkID path since afterChronicle is false
        byte[] hash1 = sigHash.createHash(tx, typeWith0x20, 0, subscript, BigInteger.valueOf(50000), null, false);

        // Same type with afterChronicle=true should use legacy path
        byte[] hash2 = sigHash.createHash(tx, typeWith0x20, 0, subscript, BigInteger.valueOf(50000), null, true);

        assertFalse("afterChronicle flag should gate CHRONICLE interpretation",
                java.util.Arrays.equals(hash1, hash2));
    }
}
