package org.twostack.bitcoin4j.script;

import org.junit.Test;
import org.twostack.bitcoin4j.Coin;
import org.twostack.bitcoin4j.Utils;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.*;
import static org.twostack.bitcoin4j.script.ScriptOpCodes.*;

public class ScriptTraceCallbackTest {

    private static final Set<Script.VerifyFlag> FLAGS = EnumSet.of(
            Script.VerifyFlag.UTXO_AFTER_GENESIS
    );

    @Test
    public void traceCallbackReceivesOpcodeSteps() {
        // Script: OP_1 OP_2 OP_ADD → should produce 3 steps
        Script script = new ScriptBuilder()
                .op(OP_1)
                .op(OP_2)
                .op(OP_ADD)
                .build();

        LinkedList<byte[]> stack = new LinkedList<>();
        List<String> traceLog = new ArrayList<>();

        ScriptTraceCallback callback = (pc, opcode, opName, s, alt) -> {
            traceLog.add(opName + " pc=" + pc + " stackSize=" + s.size());
        };

        Interpreter.executeScript(null, 0, script, stack, Coin.ZERO, FLAGS, null, callback);

        assertEquals(3, traceLog.size());
        // ScriptOpCodes names are without "OP_" prefix (e.g. "1", "2", "ADD")
        assertTrue(traceLog.get(0).startsWith("1 "));
        assertTrue(traceLog.get(1).startsWith("2 "));
        assertTrue(traceLog.get(2).startsWith("ADD "));

        // Stack should have [3]
        assertEquals(1, stack.size());
    }

    @Test
    public void traceCallbackShowsStackState() {
        // Track stack state at each step
        Script script = new ScriptBuilder()
                .op(OP_1)
                .op(OP_DUP)
                .build();

        LinkedList<byte[]> stack = new LinkedList<>();
        List<Integer> stackSizes = new ArrayList<>();

        ScriptTraceCallback callback = (pc, opcode, opName, s, alt) -> {
            stackSizes.add(s.size());
        };

        Interpreter.executeScript(null, 0, script, stack, Coin.ZERO, FLAGS, null, callback);

        assertEquals(2, stackSizes.size());
        assertEquals(Integer.valueOf(1), stackSizes.get(0)); // after OP_1: [1]
        assertEquals(Integer.valueOf(2), stackSizes.get(1)); // after OP_DUP: [1, 1]
    }

    @Test
    public void traceCallbackShowsAltStackState() {
        // OP_1 OP_TOALTSTACK — should show altstack populated
        Script script = new ScriptBuilder()
                .op(OP_1)
                .op(OP_TOALTSTACK)
                .op(OP_1) // push something to main stack so script succeeds
                .build();

        LinkedList<byte[]> stack = new LinkedList<>();
        List<Integer> altStackSizes = new ArrayList<>();

        ScriptTraceCallback callback = (pc, opcode, opName, s, alt) -> {
            altStackSizes.add(alt.size());
        };

        Interpreter.executeScript(null, 0, script, stack, Coin.ZERO, FLAGS, null, callback);

        assertEquals(3, altStackSizes.size());
        assertEquals(Integer.valueOf(0), altStackSizes.get(0)); // after OP_1: alt empty
        assertEquals(Integer.valueOf(1), altStackSizes.get(1)); // after OP_TOALTSTACK: alt has 1
        assertEquals(Integer.valueOf(1), altStackSizes.get(2)); // after OP_1: alt still 1
    }

    @Test
    public void nullTraceCallbackDoesNothing() {
        // Verify that null callback doesn't cause issues
        Script script = new ScriptBuilder()
                .op(OP_1)
                .build();

        LinkedList<byte[]> stack = new LinkedList<>();
        Interpreter.executeScript(null, 0, script, stack, Coin.ZERO, FLAGS, null, null);
        assertEquals(1, stack.size());
    }
}
