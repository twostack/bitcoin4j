package org.twostack.bitcoin4j.script;

import org.junit.Test;
import org.twostack.bitcoin4j.Coin;

import java.util.EnumSet;
import java.util.LinkedList;
import java.util.Set;

import static org.junit.Assert.*;
import static org.twostack.bitcoin4j.script.ScriptOpCodes.*;

public class ScriptDiagnosticsTest {

    private static final Set<Script.VerifyFlag> FLAGS = EnumSet.of(
            Script.VerifyFlag.UTXO_AFTER_GENESIS
    );

    @Test
    public void scriptExceptionToStringIncludesErrorCode() {
        ScriptException ex = new ScriptException(ScriptError.SCRIPT_ERR_EQUALVERIFY, "test message");
        String str = ex.toString();
        assertTrue(str.contains("SCRIPT_ERR_EQUALVERIFY"));
        assertTrue(str.contains("test message"));
        assertTrue(str.startsWith("ScriptException["));
    }

    @Test
    public void scriptExceptionToStringIncludesCause() {
        RuntimeException cause = new RuntimeException("root cause");
        ScriptException ex = new ScriptException(ScriptError.SCRIPT_ERR_EVAL_FALSE, "wrapper", cause);
        String str = ex.toString();
        assertTrue(str.contains("root cause"));
        assertTrue(str.contains("caused by"));
    }

    @Test
    public void opEqualVerifyErrorIncludesHexValues() {
        // Push two different values and do EQUALVERIFY — should fail with hex in message
        Script script = new ScriptBuilder()
                .data(new byte[]{0x01, 0x02})
                .data(new byte[]{0x03, 0x04})
                .op(OP_EQUALVERIFY)
                .build();

        LinkedList<byte[]> stack = new LinkedList<>();

        try {
            Interpreter.executeScript(null, 0, script, stack, Coin.ZERO, FLAGS);
            fail("Expected ScriptException");
        } catch (ScriptException e) {
            assertTrue("Error should contain hex of first value", e.getMessage().contains("0304"));
            assertTrue("Error should contain hex of second value", e.getMessage().contains("0102"));
            assertTrue("Error should contain byte count", e.getMessage().contains("2 bytes"));
        }
    }

    @Test
    public void opSplitErrorIncludesPositionAndLength() {
        // Push a 2-byte value and try to split at position 5
        Script script = new ScriptBuilder()
                .data(new byte[]{0x0A, 0x0B})
                .op(OP_5)
                .op(OP_SPLIT)
                .build();

        LinkedList<byte[]> stack = new LinkedList<>();

        try {
            Interpreter.executeScript(null, 0, script, stack, Coin.ZERO, FLAGS);
            fail("Expected ScriptException");
        } catch (ScriptException e) {
            assertTrue("Error should contain position", e.getMessage().contains("position=5"));
            assertTrue("Error should contain data length", e.getMessage().contains("length=2"));
            assertTrue("Error should contain hex", e.getMessage().contains("0a0b"));
        }
    }
}
