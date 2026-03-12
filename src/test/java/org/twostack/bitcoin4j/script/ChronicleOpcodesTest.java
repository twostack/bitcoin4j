package org.twostack.bitcoin4j.script;

import org.junit.Test;
import org.twostack.bitcoin4j.Coin;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.transaction.Transaction;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.EnumSet;
import java.util.LinkedList;
import java.util.Set;

import static org.junit.Assert.*;
import static org.twostack.bitcoin4j.script.ScriptOpCodes.*;

public class ChronicleOpcodesTest {

    private static final Set<Script.VerifyFlag> CHRONICLE_FLAGS = EnumSet.of(
            Script.VerifyFlag.UTXO_AFTER_GENESIS,
            Script.VerifyFlag.AFTER_CHRONICLE
    );

    private static final Set<Script.VerifyFlag> PRE_CHRONICLE_FLAGS = EnumSet.of(
            Script.VerifyFlag.UTXO_AFTER_GENESIS
    );

    private void executeScript(Script script, LinkedList<byte[]> stack, Set<Script.VerifyFlag> flags) {
        Interpreter.executeScript(null, 0, script, stack, Coin.ZERO, flags);
    }

    // ==================== OP_SUBSTR ====================

    @Test
    public void opSubstrExtractsSubstring() {
        LinkedList<byte[]> stack = new LinkedList<>();
        stack.add(new byte[]{0x01, 0x02, 0x03, 0x04, 0x05}); // string
        stack.add(new byte[]{0x01}); // begin = 1
        stack.add(new byte[]{0x03}); // length = 3

        Script script = new ScriptBuilder().op(OP_SUBSTR).build();
        executeScript(script, stack, CHRONICLE_FLAGS);

        assertEquals(1, stack.size());
        assertArrayEquals(new byte[]{0x02, 0x03, 0x04}, stack.getLast());
    }

    @Test(expected = ScriptException.class)
    public void opSubstrFailsOnOutOfBounds() {
        LinkedList<byte[]> stack = new LinkedList<>();
        stack.add(new byte[]{0x01, 0x02}); // string of length 2
        stack.add(new byte[]{0x00}); // begin = 0
        stack.add(new byte[]{0x05}); // length = 5 (out of bounds)

        Script script = new ScriptBuilder().op(OP_SUBSTR).build();
        executeScript(script, stack, CHRONICLE_FLAGS);
    }

    @Test
    public void opSubstrTreatedAsNopPreChronicle() {
        LinkedList<byte[]> stack = new LinkedList<>();
        stack.add(new byte[]{0x01});
        stack.add(new byte[]{0x00});
        stack.add(new byte[]{0x01});

        Script script = new ScriptBuilder().op(OP_NOP4).build(); // == OP_SUBSTR
        executeScript(script, stack, PRE_CHRONICLE_FLAGS);

        // Stack unchanged — NOP behavior
        assertEquals(3, stack.size());
    }

    // ==================== OP_LEFT ====================

    @Test
    public void opLeftExtractsLeftBytes() {
        LinkedList<byte[]> stack = new LinkedList<>();
        stack.add(new byte[]{0x0A, 0x0B, 0x0C, 0x0D}); // string
        stack.add(new byte[]{0x02}); // length = 2

        Script script = new ScriptBuilder().op(OP_LEFT).build();
        executeScript(script, stack, CHRONICLE_FLAGS);

        assertEquals(1, stack.size());
        assertArrayEquals(new byte[]{0x0A, 0x0B}, stack.getLast());
    }

    @Test(expected = ScriptException.class)
    public void opLeftFailsOnLengthExceeded() {
        LinkedList<byte[]> stack = new LinkedList<>();
        stack.add(new byte[]{0x01, 0x02}); // 2 bytes
        stack.add(new byte[]{0x05}); // want 5

        Script script = new ScriptBuilder().op(OP_LEFT).build();
        executeScript(script, stack, CHRONICLE_FLAGS);
    }

    // ==================== OP_RIGHT ====================

    @Test
    public void opRightExtractsRightBytes() {
        LinkedList<byte[]> stack = new LinkedList<>();
        stack.add(new byte[]{0x0A, 0x0B, 0x0C, 0x0D}); // string
        stack.add(new byte[]{0x02}); // length = 2

        Script script = new ScriptBuilder().op(OP_RIGHT).build();
        executeScript(script, stack, CHRONICLE_FLAGS);

        assertEquals(1, stack.size());
        assertArrayEquals(new byte[]{0x0C, 0x0D}, stack.getLast());
    }

    @Test(expected = ScriptException.class)
    public void opRightFailsOnLengthExceeded() {
        LinkedList<byte[]> stack = new LinkedList<>();
        stack.add(new byte[]{0x01}); // 1 byte
        stack.add(new byte[]{0x03}); // want 3

        Script script = new ScriptBuilder().op(OP_RIGHT).build();
        executeScript(script, stack, CHRONICLE_FLAGS);
    }

    // ==================== OP_LSHIFTNUM ====================

    @Test
    public void opLshiftnumShiftsLeft() {
        LinkedList<byte[]> stack = new LinkedList<>();
        stack.add(new byte[]{0x04}); // num = 4
        stack.add(new byte[]{0x02}); // shift = 2

        Script script = new ScriptBuilder().op(OP_LSHIFTNUM).build();
        executeScript(script, stack, CHRONICLE_FLAGS);

        assertEquals(1, stack.size());
        // 4 << 2 = 16
        BigInteger result = Utils.decodeMPI(Utils.reverseBytes(stack.getLast()), false);
        assertEquals(BigInteger.valueOf(16), result);
    }

    // ==================== OP_RSHIFTNUM ====================

    @Test
    public void opRshiftnumShiftsRight() {
        LinkedList<byte[]> stack = new LinkedList<>();
        stack.add(new byte[]{0x10}); // num = 16
        stack.add(new byte[]{0x02}); // shift = 2

        Script script = new ScriptBuilder().op(OP_RSHIFTNUM).build();
        executeScript(script, stack, CHRONICLE_FLAGS);

        assertEquals(1, stack.size());
        // 16 >> 2 = 4
        BigInteger result = Utils.decodeMPI(Utils.reverseBytes(stack.getLast()), false);
        assertEquals(BigInteger.valueOf(4), result);
    }

    // ==================== OP_2MUL ====================

    @Test
    public void op2MulMultipliesBy2() {
        LinkedList<byte[]> stack = new LinkedList<>();
        stack.add(new byte[]{0x07}); // num = 7

        Script script = new ScriptBuilder().op(OP_2MUL).build();
        executeScript(script, stack, CHRONICLE_FLAGS);

        assertEquals(1, stack.size());
        BigInteger result = Utils.decodeMPI(Utils.reverseBytes(stack.getLast()), false);
        assertEquals(BigInteger.valueOf(14), result);
    }

    @Test(expected = ScriptException.class)
    public void op2MulDisabledPreChronicle() {
        LinkedList<byte[]> stack = new LinkedList<>();
        stack.add(new byte[]{0x07});

        Script script = new ScriptBuilder().op(OP_2MUL).build();
        executeScript(script, stack, PRE_CHRONICLE_FLAGS);
    }

    // ==================== OP_2DIV ====================

    @Test
    public void op2DivDividesBy2() {
        LinkedList<byte[]> stack = new LinkedList<>();
        stack.add(new byte[]{0x0A}); // num = 10

        Script script = new ScriptBuilder().op(OP_2DIV).build();
        executeScript(script, stack, CHRONICLE_FLAGS);

        assertEquals(1, stack.size());
        BigInteger result = Utils.decodeMPI(Utils.reverseBytes(stack.getLast()), false);
        assertEquals(BigInteger.valueOf(5), result);
    }

    @Test(expected = ScriptException.class)
    public void op2DivDisabledPreChronicle() {
        LinkedList<byte[]> stack = new LinkedList<>();
        stack.add(new byte[]{0x0A});

        Script script = new ScriptBuilder().op(OP_2DIV).build();
        executeScript(script, stack, PRE_CHRONICLE_FLAGS);
    }

    // ==================== OP_VER ====================

    @Test
    public void opVerPushesTransactionVersion() throws IOException {
        // Create a v2 transaction
        Transaction tx = new Transaction();
        tx.setVersion(2);

        LinkedList<byte[]> stack = new LinkedList<>();

        Script script = new ScriptBuilder().op(OP_VER).build();
        Interpreter.executeScript(tx, 0, script, stack, Coin.ZERO, CHRONICLE_FLAGS);

        assertEquals(1, stack.size());
        BigInteger version = Utils.decodeMPI(Utils.reverseBytes(stack.getLast()), false);
        assertEquals(BigInteger.valueOf(2), version);
    }

    @Test(expected = ScriptException.class)
    public void opVerDisabledPreChronicle() {
        LinkedList<byte[]> stack = new LinkedList<>();

        Script script = new ScriptBuilder().op(OP_VER).build();
        executeScript(script, stack, PRE_CHRONICLE_FLAGS);
    }

    // ==================== OP_VERIF / OP_VERNOTIF ====================

    @Test
    public void opVerifBranchesTrueWhenVersionMet() throws IOException {
        Transaction tx = new Transaction();
        tx.setVersion(2);

        LinkedList<byte[]> stack = new LinkedList<>();
        stack.add(new byte[]{0x02}); // comparison = 2

        // OP_VERIF <2> → version(2) >= 2 → true branch
        // In true branch: push OP_1, then OP_ENDIF
        Script script = new ScriptBuilder()
                .op(OP_VERIF)
                .op(OP_1)
                .op(OP_ENDIF)
                .build();

        Interpreter.executeScript(tx, 0, script, stack, Coin.ZERO, CHRONICLE_FLAGS);

        // OP_1 should have been executed
        assertEquals(1, stack.size());
    }

    @Test
    public void opVerifBranchesFalseWhenVersionNotMet() throws IOException {
        Transaction tx = new Transaction();
        tx.setVersion(1);

        LinkedList<byte[]> stack = new LinkedList<>();
        stack.add(new byte[]{0x02}); // comparison = 2

        // version(1) >= 2 → false → skip to ENDIF
        Script script = new ScriptBuilder()
                .op(OP_VERIF)
                .op(OP_1)
                .op(OP_ENDIF)
                .build();

        Interpreter.executeScript(tx, 0, script, stack, Coin.ZERO, CHRONICLE_FLAGS);

        // OP_1 should NOT have been executed, stack should be empty
        assertEquals(0, stack.size());
    }

    @Test
    public void opVernotifBranchesTrueWhenVersionLess() throws IOException {
        Transaction tx = new Transaction();
        tx.setVersion(1);

        LinkedList<byte[]> stack = new LinkedList<>();
        stack.add(new byte[]{0x02}); // comparison = 2

        // version(1) < 2 → true → execute body
        Script script = new ScriptBuilder()
                .op(OP_VERNOTIF)
                .op(OP_1)
                .op(OP_ENDIF)
                .build();

        Interpreter.executeScript(tx, 0, script, stack, Coin.ZERO, CHRONICLE_FLAGS);

        assertEquals(1, stack.size());
    }
}
