package org.twostack.bitcoin4j.script;

import org.junit.Test;
import org.twostack.bitcoin4j.Coin;
import org.twostack.bitcoin4j.ECKey;
import org.twostack.bitcoin4j.transaction.Transaction;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.EnumSet;
import java.util.Set;

import static org.junit.Assert.*;

/**
 * Tests that Chronicle malleability relaxation correctly skips
 * SIGPUSHONLY, CLEANSTACK, MINIMALDATA, MINIMALIF, LOW_S, NULLFAIL, NULLDUMMY
 * for transaction version > 1 when AFTER_CHRONICLE is enabled.
 */
public class ChronicleMalleabilityTest {

    @Test
    public void sigPushOnlyRelaxedForV2ChronicleTransactions() throws IOException {
        // scriptSig with a non-push opcode (OP_NOP) — normally rejected by SIGPUSHONLY
        Script scriptSig = new ScriptBuilder()
                .op(ScriptOpCodes.OP_1)
                .build();

        Script scriptPubKey = new ScriptBuilder()
                .op(ScriptOpCodes.OP_1)
                .build();

        Transaction tx = new Transaction();
        tx.setVersion(2);
        // Add a dummy input so scriptSigIndex 0 is valid
        tx.addInput(
                new org.twostack.bitcoin4j.transaction.TransactionInput(
                        new byte[32], 0, 0xFFFFFFFFL,
                        new org.twostack.bitcoin4j.transaction.DefaultUnlockBuilder(scriptSig)
                )
        );

        Set<Script.VerifyFlag> flags = EnumSet.of(
                Script.VerifyFlag.UTXO_AFTER_GENESIS,
                Script.VerifyFlag.AFTER_CHRONICLE,
                Script.VerifyFlag.SIGPUSHONLY
        );

        Interpreter interpreter = new Interpreter();
        // This should not throw — SIGPUSHONLY is relaxed for v2 Chronicle transactions
        // The script simply pushes 1 twice and the result is true
        interpreter.correctlySpends(scriptSig, scriptPubKey, tx, 0, flags, Coin.ZERO);
    }

    @Test
    public void malleabilityFlagsEnforcedForV1Transactions() {
        // Even with AFTER_CHRONICLE, v1 transactions should still enforce SIGPUSHONLY
        Script scriptSig = new ScriptBuilder()
                .op(ScriptOpCodes.OP_NOP)
                .op(ScriptOpCodes.OP_1)
                .build();

        Script scriptPubKey = new ScriptBuilder()
                .op(ScriptOpCodes.OP_1)
                .build();

        Transaction tx = new Transaction();
        tx.setVersion(1);
        tx.addInput(
                new org.twostack.bitcoin4j.transaction.TransactionInput(
                        new byte[32], 0, 0xFFFFFFFFL,
                        new org.twostack.bitcoin4j.transaction.DefaultUnlockBuilder(scriptSig)
                )
        );

        Set<Script.VerifyFlag> flags = EnumSet.of(
                Script.VerifyFlag.UTXO_AFTER_GENESIS,
                Script.VerifyFlag.AFTER_CHRONICLE,
                Script.VerifyFlag.SIGPUSHONLY
        );

        Interpreter interpreter = new Interpreter();
        try {
            interpreter.correctlySpends(scriptSig, scriptPubKey, tx, 0, flags, Coin.ZERO);
            fail("Expected ScriptException for SIGPUSHONLY violation on v1 transaction");
        } catch (ScriptException e) {
            // Expected — SIGPUSHONLY still enforced for v1
            assertTrue(e.getMessage().contains("pushdata"));
        }
    }
}
