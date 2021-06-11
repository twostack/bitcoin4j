package org.twostack.bitcoin.script;

import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.twostack.bitcoin.ECKey;
import org.twostack.bitcoin.Sha256Hash;
import org.twostack.bitcoin.UnsafeByteArrayOutputStream;
import org.twostack.bitcoin.Utils;
import org.twostack.bitcoin.exception.SignatureDecodeException;
import org.twostack.bitcoin.exception.VerificationException;
import org.twostack.bitcoin.transaction.Transaction;
import org.twostack.bitcoin.transaction.TransactionInput;
import org.twostack.bitcoin.transaction.TransactionSignature;
import org.twostack.bitcoin.transaction.TransactionSigner;

import javax.annotation.Nullable;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static com.google.common.base.Preconditions.checkArgument;
import static org.twostack.bitcoin.script.Script.*;
import static org.twostack.bitcoin.script.ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION;
import static org.twostack.bitcoin.script.ScriptOpCodes.*;

public class Interpreter {

    private static final Logger log = LoggerFactory.getLogger(Script.class);

    public static final long MAX_SCRIPT_ELEMENT_SIZE = 520;  // bytes
    private static final int MAX_OPS_PER_SCRIPT = 201;
    private static final int MAX_STACK_SIZE = 1000;
    private static final int MAX_PUBKEYS_PER_MULTISIG = 20;
    private static final int MAX_SCRIPT_SIZE = 10000;
    public static final int SIG_SIZE = 75;
    /** Max number of sigops allowed in a standard p2sh redeem script */
    public static final int MAX_P2SH_SIGOPS = 15;


    ////////////////////// Script verification and helpers ////////////////////////////////

    private static boolean castToBool(byte[] data) {
        for (int i = 0; i < data.length; i++)
        {
            // "Can be negative zero" - Bitcoin Core (see OpenSSL's BN_bn2mpi)
            if (data[i] != 0)
                return !(i == data.length - 1 && (data[i] & 0xFF) == 0x80);
        }
        return false;
    }

    /**
     * Cast a script chunk to a BigInteger.
     *
     * @see #castToBigInteger(byte[], int, boolean) for values with different maximum
     * sizes.
     * @throws ScriptException if the chunk is longer than 4 bytes.
     */
    private static BigInteger castToBigInteger(byte[] chunk, final boolean requireMinimal) throws ScriptException {
        return castToBigInteger(chunk, 4, requireMinimal);
    }

    /**
     * Cast a script chunk to a BigInteger. Normally you would want
     * {@link #castToBigInteger(byte[], boolean)} instead, this is only for cases where
     * the normal maximum length does not apply (i.e. CHECKLOCKTIMEVERIFY, CHECKSEQUENCEVERIFY).
     *
     * @param maxLength the maximum length in bytes.
     * @param requireMinimal check if the number is encoded with the minimum possible number of bytes
     * @throws ScriptException if the chunk is longer than the specified maximum.
     */
    /* package private */ static BigInteger castToBigInteger(final byte[] chunk, final int maxLength, final boolean requireMinimal) throws ScriptException {
        if (chunk.length > maxLength)
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Script attempted to use an integer larger than " + maxLength + " bytes");

        if (requireMinimal && chunk.length > 0) {
            // Check that the number is encoded with the minimum possible
            // number of bytes.
            //
            // If the most-significant-byte - excluding the sign bit - is zero
            // then we're not minimal. Note how this test also rejects the
            // negative-zero encoding, 0x80.
            if ((chunk[chunk.length - 1] & 0x7f) == 0) {
                // One exception: if there's more than one byte and the most
                // significant bit of the second-most-significant-byte is set
                // it would conflict with the sign bit. An example of this case
                // is +-255, which encode to 0xff00 and 0xff80 respectively.
                // (big-endian).
                if (chunk.length <= 1 || (chunk[chunk.length - 2] & 0x80) == 0) {
                    throw  new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "non-minimally encoded script number");
                }
            }
        }

        return Utils.decodeMPI(Utils.reverseBytes(chunk), false);
    }

    /** @deprecated use {@link ScriptPattern#isOpReturn(Script)} */
    @Deprecated
    public boolean isOpReturn(Script script) {
        return ScriptPattern.isOpReturn(script);
    }


    public int decodeFromOpN(int opcode) {
        checkArgument((opcode == OP_0 || opcode == OP_1NEGATE) || (opcode >= OP_1 && opcode <= OP_16),
                "decodeFromOpN called on non OP_N opcode: %s", ScriptOpCodes.getOpCodeName(opcode));
        if (opcode == OP_0)
            return 0;
        else if (opcode == OP_1NEGATE)
            return -1;
        else
            return opcode + 1 - OP_1;
    }

    public int encodeToOpN(int value) {
        checkArgument(value >= -1 && value <= 16, "encodeToOpN called for " + value + " which we cannot encode in an opcode.");
        if (value == 0)
            return OP_0;
        else if (value == -1)
            return OP_1NEGATE;
        else
            return value - 1 + OP_1;
    }

    /**
     * Gets the count of regular SigOps in the script program (counting multisig ops as 20)
     */
    public int getSigOpCount(byte[] program) throws ScriptException {

        Script script = new ScriptBuilder().build();
        try {
            script = Script.fromByteArray(program);
        } catch (ScriptException e) {
            // Ignore errors and count up to the parse-able length
        }
        return Script.getSigOpCount(script.chunks, false);
    }


    public void executeScript(@Nullable Transaction txContainingThis, long index,
                                     Script script, LinkedList<byte[]> stack, Set<VerifyFlag> verifyFlags) throws ScriptException {
        int opCount = 0;
        int lastCodeSepLocation = 0;

        LinkedList<byte[]> altstack = new LinkedList<>();
        LinkedList<Boolean> ifStack = new LinkedList<>();

        int nextLocationInScript = 0;
        for (ScriptChunk chunk : script.chunks) {
            boolean shouldExecute = !ifStack.contains(false);
            int opcode = chunk.opcode;
            nextLocationInScript += chunk.size();

            // Check stack element size
            if (chunk.data != null && chunk.data.length > MAX_SCRIPT_ELEMENT_SIZE)
                throw new ScriptException(ScriptError.SCRIPT_ERR_PUSH_SIZE, "Attempted to push a data string larger than 520 bytes");

            // Note how OP_RESERVED does not count towards the opcode limit.
            if (opcode > OP_16) {
                opCount++;
                if (opCount > MAX_OPS_PER_SCRIPT)
                    throw new ScriptException(ScriptError.SCRIPT_ERR_OP_COUNT, "More script operations than is allowed");
            }

            // Disabled opcodes.
            if (opcode == OP_CAT || opcode == OP_SUBSTR || opcode == OP_LEFT || opcode == OP_RIGHT ||
                    opcode == OP_INVERT || opcode == OP_AND || opcode == OP_OR || opcode == OP_XOR ||
                    opcode == OP_2MUL || opcode == OP_2DIV || opcode == OP_MUL || opcode == OP_DIV ||
                    opcode == OP_MOD || opcode == OP_LSHIFT || opcode == OP_RSHIFT)
                throw new ScriptException(ScriptError.SCRIPT_ERR_DISABLED_OPCODE, "Script included a disabled Script Op.");

            if (shouldExecute && OP_0 <= opcode && opcode <= OP_PUSHDATA4) {
                // Check minimal push
                if (verifyFlags.contains(VerifyFlag.MINIMALDATA) && !chunk.isShortestPossiblePushData())
                    throw new ScriptException(ScriptError.SCRIPT_ERR_MINIMALDATA, "Script included a not minimal push operation.");

                if (opcode == OP_0)
                    stack.add(new byte[]{});
                else
                    stack.add(chunk.data);
            } else if (shouldExecute || (OP_IF <= opcode && opcode <= OP_ENDIF)){

                switch (opcode) {
                    case OP_IF:
                        if (!shouldExecute) {
                            ifStack.add(false);
                            continue;
                        }
                        if (stack.size() < 1)
                            throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "Attempted OP_IF on an empty stack");
                        ifStack.add(castToBool(stack.pollLast()));
                        continue;
                    case OP_NOTIF:
                        if (!shouldExecute) {
                            ifStack.add(false);
                            continue;
                        }
                        if (stack.size() < 1)
                            throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "Attempted OP_NOTIF on an empty stack");
                        ifStack.add(!castToBool(stack.pollLast()));
                        continue;
                    case OP_ELSE:
                        if (ifStack.isEmpty())
                            throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "Attempted OP_ELSE without OP_IF/NOTIF");
                        ifStack.add(!ifStack.pollLast());
                        continue;
                    case OP_ENDIF:
                        if (ifStack.isEmpty())
                            throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "Attempted OP_ENDIF without OP_IF/NOTIF");
                        ifStack.pollLast();
                        continue;

                        // OP_0 is no opcode
                    case OP_1NEGATE:
                        stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.ONE.negate(), false)));
                        break;
                    case OP_1:
                    case OP_2:
                    case OP_3:
                    case OP_4:
                    case OP_5:
                    case OP_6:
                    case OP_7:
                    case OP_8:
                    case OP_9:
                    case OP_10:
                    case OP_11:
                    case OP_12:
                    case OP_13:
                    case OP_14:
                    case OP_15:
                    case OP_16:
                        stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.valueOf(decodeFromOpN(opcode)), false)));
                        break;
                    case OP_NOP:
                        break;
                    case OP_VERIFY:
                        if (stack.size() < 1)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_VERIFY on an empty stack");
                        if (!castToBool(stack.pollLast()))
                            throw new ScriptException(ScriptError.SCRIPT_ERR_VERIFY, "OP_VERIFY failed");
                        break;
                    case OP_RETURN:
                        throw new ScriptException(ScriptError.SCRIPT_ERR_OP_RETURN, "Script called OP_RETURN");
                    case OP_TOALTSTACK:
                        if (stack.size() < 1)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_TOALTSTACK on an empty stack");
                        altstack.add(stack.pollLast());
                        break;
                    case OP_FROMALTSTACK:
                        if (altstack.size() < 1)
                            throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_ALTSTACK_OPERATION, "Attempted OP_FROMALTSTACK on an empty altstack");
                        stack.add(altstack.pollLast());
                        break;
                    case OP_2DROP:
                        if (stack.size() < 2)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_2DROP on a stack with size < 2");
                        stack.pollLast();
                        stack.pollLast();
                        break;
                    case OP_2DUP:
                        if (stack.size() < 2)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_2DUP on a stack with size < 2");
                        Iterator<byte[]> it2DUP = stack.descendingIterator();
                        byte[] OP2DUPtmpChunk2 = it2DUP.next();
                        stack.add(it2DUP.next());
                        stack.add(OP2DUPtmpChunk2);
                        break;
                    case OP_3DUP:
                        if (stack.size() < 3)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_3DUP on a stack with size < 3");
                        Iterator<byte[]> it3DUP = stack.descendingIterator();
                        byte[] OP3DUPtmpChunk3 = it3DUP.next();
                        byte[] OP3DUPtmpChunk2 = it3DUP.next();
                        stack.add(it3DUP.next());
                        stack.add(OP3DUPtmpChunk2);
                        stack.add(OP3DUPtmpChunk3);
                        break;
                    case OP_2OVER:
                        if (stack.size() < 4)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_2OVER on a stack with size < 4");
                        Iterator<byte[]> it2OVER = stack.descendingIterator();
                        it2OVER.next();
                        it2OVER.next();
                        byte[] OP2OVERtmpChunk2 = it2OVER.next();
                        stack.add(it2OVER.next());
                        stack.add(OP2OVERtmpChunk2);
                        break;
                    case OP_2ROT:
                        if (stack.size() < 6)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_2ROT on a stack with size < 6");
                        byte[] OP2ROTtmpChunk6 = stack.pollLast();
                        byte[] OP2ROTtmpChunk5 = stack.pollLast();
                        byte[] OP2ROTtmpChunk4 = stack.pollLast();
                        byte[] OP2ROTtmpChunk3 = stack.pollLast();
                        byte[] OP2ROTtmpChunk2 = stack.pollLast();
                        byte[] OP2ROTtmpChunk1 = stack.pollLast();
                        stack.add(OP2ROTtmpChunk3);
                        stack.add(OP2ROTtmpChunk4);
                        stack.add(OP2ROTtmpChunk5);
                        stack.add(OP2ROTtmpChunk6);
                        stack.add(OP2ROTtmpChunk1);
                        stack.add(OP2ROTtmpChunk2);
                        break;
                    case OP_2SWAP:
                        if (stack.size() < 4)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_2SWAP on a stack with size < 4");
                        byte[] OP2SWAPtmpChunk4 = stack.pollLast();
                        byte[] OP2SWAPtmpChunk3 = stack.pollLast();
                        byte[] OP2SWAPtmpChunk2 = stack.pollLast();
                        byte[] OP2SWAPtmpChunk1 = stack.pollLast();
                        stack.add(OP2SWAPtmpChunk3);
                        stack.add(OP2SWAPtmpChunk4);
                        stack.add(OP2SWAPtmpChunk1);
                        stack.add(OP2SWAPtmpChunk2);
                        break;
                    case OP_IFDUP:
                        if (stack.size() < 1)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_IFDUP on an empty stack");
                        if (castToBool(stack.getLast()))
                            stack.add(stack.getLast());
                        break;
                    case OP_DEPTH:
                        stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.valueOf(stack.size()), false)));
                        break;
                    case OP_DROP:
                        if (stack.size() < 1)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_DROP on an empty stack");
                        stack.pollLast();
                        break;
                    case OP_DUP:
                        if (stack.size() < 1)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_DUP on an empty stack");
                        stack.add(stack.getLast());
                        break;
                    case OP_NIP:
                        if (stack.size() < 2)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_NIP on a stack with size < 2");
                        byte[] OPNIPtmpChunk = stack.pollLast();
                        stack.pollLast();
                        stack.add(OPNIPtmpChunk);
                        break;
                    case OP_OVER:
                        if (stack.size() < 2)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_OVER on a stack with size < 2");
                        Iterator<byte[]> itOVER = stack.descendingIterator();
                        itOVER.next();
                        stack.add(itOVER.next());
                        break;
                    case OP_PICK:
                    case OP_ROLL:
                        if (stack.size() < 1)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_PICK/OP_ROLL on an empty stack");
                        long val = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA)).longValue();
                        if (val < 0 || val >= stack.size())
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "OP_PICK/OP_ROLL attempted to get data deeper than stack size");
                        Iterator<byte[]> itPICK = stack.descendingIterator();
                        for (long i = 0; i < val; i++)
                            itPICK.next();
                        byte[] OPROLLtmpChunk = itPICK.next();
                        if (opcode == OP_ROLL)
                            itPICK.remove();
                        stack.add(OPROLLtmpChunk);
                        break;
                    case OP_ROT:
                        if (stack.size() < 3)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_ROT on a stack with size < 3");
                        byte[] OPROTtmpChunk3 = stack.pollLast();
                        byte[] OPROTtmpChunk2 = stack.pollLast();
                        byte[] OPROTtmpChunk1 = stack.pollLast();
                        stack.add(OPROTtmpChunk2);
                        stack.add(OPROTtmpChunk3);
                        stack.add(OPROTtmpChunk1);
                        break;
                    case OP_SWAP:
                    case OP_TUCK:
                        if (stack.size() < 2)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_SWAP on a stack with size < 2");
                        byte[] OPSWAPtmpChunk2 = stack.pollLast();
                        byte[] OPSWAPtmpChunk1 = stack.pollLast();
                        stack.add(OPSWAPtmpChunk2);
                        stack.add(OPSWAPtmpChunk1);
                        if (opcode == OP_TUCK)
                            stack.add(OPSWAPtmpChunk2);
                        break;
                    case OP_SIZE:
                        if (stack.size() < 1)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_SIZE on an empty stack");
                        stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.valueOf(stack.getLast().length), false)));
                        break;
                    case OP_EQUAL:
                        if (stack.size() < 2)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_EQUAL on a stack with size < 2");
                        stack.add(Arrays.equals(stack.pollLast(), stack.pollLast()) ? new byte[] {1} : new byte[] {});
                        break;
                    case OP_EQUALVERIFY:
                        if (stack.size() < 2)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_EQUALVERIFY on a stack with size < 2");
                        if (!Arrays.equals(stack.pollLast(), stack.pollLast()))
                            throw new ScriptException(ScriptError.SCRIPT_ERR_EQUALVERIFY, "OP_EQUALVERIFY: non-equal data");
                        break;
                    case OP_1ADD:
                    case OP_1SUB:
                    case OP_NEGATE:
                    case OP_ABS:
                    case OP_NOT:
                    case OP_0NOTEQUAL:
                        if (stack.size() < 1)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted a numeric op on an empty stack");
                        BigInteger numericOPnum = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA));

                        switch (opcode) {
                            case OP_1ADD:
                                numericOPnum = numericOPnum.add(BigInteger.ONE);
                                break;
                            case OP_1SUB:
                                numericOPnum = numericOPnum.subtract(BigInteger.ONE);
                                break;
                            case OP_NEGATE:
                                numericOPnum = numericOPnum.negate();
                                break;
                            case OP_ABS:
                                if (numericOPnum.signum() < 0)
                                    numericOPnum = numericOPnum.negate();
                                break;
                            case OP_NOT:
                                if (numericOPnum.equals(BigInteger.ZERO))
                                    numericOPnum = BigInteger.ONE;
                                else
                                    numericOPnum = BigInteger.ZERO;
                                break;
                            case OP_0NOTEQUAL:
                                if (numericOPnum.equals(BigInteger.ZERO))
                                    numericOPnum = BigInteger.ZERO;
                                else
                                    numericOPnum = BigInteger.ONE;
                                break;
                            default:
                                throw new AssertionError("Unreachable");
                        }

                        stack.add(Utils.reverseBytes(Utils.encodeMPI(numericOPnum, false)));
                        break;
                    case OP_ADD:
                    case OP_SUB:
                    case OP_BOOLAND:
                    case OP_BOOLOR:
                    case OP_NUMEQUAL:
                    case OP_NUMNOTEQUAL:
                    case OP_LESSTHAN:
                    case OP_GREATERTHAN:
                    case OP_LESSTHANOREQUAL:
                    case OP_GREATERTHANOREQUAL:
                    case OP_MIN:
                    case OP_MAX:
                        if (stack.size() < 2)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted a numeric op on a stack with size < 2");
                        BigInteger numericOPnum2 = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA));
                        BigInteger numericOPnum1 = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA));

                        BigInteger numericOPresult;
                        switch (opcode) {
                            case OP_ADD:
                                numericOPresult = numericOPnum1.add(numericOPnum2);
                                break;
                            case OP_SUB:
                                numericOPresult = numericOPnum1.subtract(numericOPnum2);
                                break;
                            case OP_BOOLAND:
                                if (!numericOPnum1.equals(BigInteger.ZERO) && !numericOPnum2.equals(BigInteger.ZERO))
                                    numericOPresult = BigInteger.ONE;
                                else
                                    numericOPresult = BigInteger.ZERO;
                                break;
                            case OP_BOOLOR:
                                if (!numericOPnum1.equals(BigInteger.ZERO) || !numericOPnum2.equals(BigInteger.ZERO))
                                    numericOPresult = BigInteger.ONE;
                                else
                                    numericOPresult = BigInteger.ZERO;
                                break;
                            case OP_NUMEQUAL:
                                if (numericOPnum1.equals(numericOPnum2))
                                    numericOPresult = BigInteger.ONE;
                                else
                                    numericOPresult = BigInteger.ZERO;
                                break;
                            case OP_NUMNOTEQUAL:
                                if (!numericOPnum1.equals(numericOPnum2))
                                    numericOPresult = BigInteger.ONE;
                                else
                                    numericOPresult = BigInteger.ZERO;
                                break;
                            case OP_LESSTHAN:
                                if (numericOPnum1.compareTo(numericOPnum2) < 0)
                                    numericOPresult = BigInteger.ONE;
                                else
                                    numericOPresult = BigInteger.ZERO;
                                break;
                            case OP_GREATERTHAN:
                                if (numericOPnum1.compareTo(numericOPnum2) > 0)
                                    numericOPresult = BigInteger.ONE;
                                else
                                    numericOPresult = BigInteger.ZERO;
                                break;
                            case OP_LESSTHANOREQUAL:
                                if (numericOPnum1.compareTo(numericOPnum2) <= 0)
                                    numericOPresult = BigInteger.ONE;
                                else
                                    numericOPresult = BigInteger.ZERO;
                                break;
                            case OP_GREATERTHANOREQUAL:
                                if (numericOPnum1.compareTo(numericOPnum2) >= 0)
                                    numericOPresult = BigInteger.ONE;
                                else
                                    numericOPresult = BigInteger.ZERO;
                                break;
                            case OP_MIN:
                                if (numericOPnum1.compareTo(numericOPnum2) < 0)
                                    numericOPresult = numericOPnum1;
                                else
                                    numericOPresult = numericOPnum2;
                                break;
                            case OP_MAX:
                                if (numericOPnum1.compareTo(numericOPnum2) > 0)
                                    numericOPresult = numericOPnum1;
                                else
                                    numericOPresult = numericOPnum2;
                                break;
                            default:
                                throw new RuntimeException("Opcode switched at runtime?");
                        }

                        stack.add(Utils.reverseBytes(Utils.encodeMPI(numericOPresult, false)));
                        break;
                    case OP_NUMEQUALVERIFY:
                        if (stack.size() < 2)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_NUMEQUALVERIFY on a stack with size < 2");
                        BigInteger OPNUMEQUALVERIFYnum2 = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA));
                        BigInteger OPNUMEQUALVERIFYnum1 = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA));

                        if (!OPNUMEQUALVERIFYnum1.equals(OPNUMEQUALVERIFYnum2))
                            throw new ScriptException(ScriptError.SCRIPT_ERR_NUMEQUALVERIFY, "OP_NUMEQUALVERIFY failed");
                        break;
                    case OP_WITHIN:
                        if (stack.size() < 3)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_WITHIN on a stack with size < 3");
                        BigInteger OPWITHINnum3 = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA));
                        BigInteger OPWITHINnum2 = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA));
                        BigInteger OPWITHINnum1 = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA));
                        if (OPWITHINnum2.compareTo(OPWITHINnum1) <= 0 && OPWITHINnum1.compareTo(OPWITHINnum3) < 0)
                            stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.ONE, false)));
                        else
                            stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.ZERO, false)));
                        break;
                    case OP_RIPEMD160:
                        if (stack.size() < 1)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_RIPEMD160 on an empty stack");
                        RIPEMD160Digest digest = new RIPEMD160Digest();
                        byte[] dataToHash = stack.pollLast();
                        digest.update(dataToHash, 0, dataToHash.length);
                        byte[] ripmemdHash = new byte[20];
                        digest.doFinal(ripmemdHash, 0);
                        stack.add(ripmemdHash);
                        break;
                    case OP_SHA1:
                        if (stack.size() < 1)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_SHA1 on an empty stack");
                        try {
                            stack.add(MessageDigest.getInstance("SHA-1").digest(stack.pollLast()));
                        } catch (NoSuchAlgorithmException e) {
                            throw new RuntimeException(e);  // Cannot happen.
                        }
                        break;
                    case OP_SHA256:
                        if (stack.size() < 1)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_SHA256 on an empty stack");
                        stack.add(Sha256Hash.hash(stack.pollLast()));
                        break;
                    case OP_HASH160:
                        if (stack.size() < 1)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_HASH160 on an empty stack");
                        stack.add(Utils.sha256hash160(stack.pollLast()));
                        break;
                    case OP_HASH256:
                        if (stack.size() < 1)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_SHA256 on an empty stack");
                        stack.add(Sha256Hash.hashTwice(stack.pollLast()));
                        break;
                    case OP_CODESEPARATOR:
                        lastCodeSepLocation = nextLocationInScript;
                        break;
                    case OP_CHECKSIG:
                    case OP_CHECKSIGVERIFY:
                        if (txContainingThis == null)
                            throw new IllegalStateException("Script attempted signature check but no tx was provided");

                        /*

                        // (sig pubkey -- bool)
                        if (stack.size() < 2) {
                            return set_error(
                                serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        }
                        LimitedVector &vchSig = stack.stacktop(-2);
                        LimitedVector &vchPubKey = stack.stacktop(-1);

                        if (!CheckSignatureEncoding(vchSig.GetElement(), flags, serror) ||
                            !CheckPubKeyEncoding(vchPubKey.GetElement(), flags, serror)) {
                            // serror is set
                            return false;
                        }

                        // Subset of script starting at the most recent
                        // codeseparator
                        CScript scriptCode(pbegincodehash, pend);

                        // Remove signature for pre-fork scripts
                        CleanupScriptCode(scriptCode, vchSig.GetElement(), flags);

                        bool fSuccess = checker.CheckSig(vchSig.GetElement(), vchPubKey.GetElement(),
                                                         scriptCode, flags & SCRIPT_ENABLE_SIGHASH_FORKID);

                        if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) &&
                            vchSig.size()) {
                            return set_error(serror, SCRIPT_ERR_SIG_NULLFAIL);
                        }

                        stack.pop_back();
                        stack.pop_back();
                        stack.push_back(fSuccess ? vchTrue : vchFalse);
                        if (opcode == OP_CHECKSIGVERIFY) {
                            if (fSuccess) {
                                stack.pop_back();
                            } else {
                                return set_error(serror,
                                                 SCRIPT_ERR_CHECKSIGVERIFY);
                            }
                        }
                    } break;
                         */


                        break;
                    case OP_CHECKMULTISIG:
                    case OP_CHECKMULTISIGVERIFY:
                        if (txContainingThis == null)
                            throw new IllegalStateException("Script attempted signature check but no tx was provided");


                        // ([sig ...] num_of_signatures [pubkey ...]
                        // num_of_pubkeys -- bool)

                        int i = 1;
                        if (stack.size() < i) {
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_CHECKLOCKTIMEVERIFY on a stack with size < 1");
                        }

                        /*
                        // initialize to max size of CScriptNum::MAXIMUM_ELEMENT_SIZE (4 bytes)
                        // because only 4 byte integers are supported by  OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY
                        int64_t nKeysCountSigned =
                            CScriptNum(stack.stacktop(-i).GetElement(), fRequireMinimal, CScriptNum::MAXIMUM_ELEMENT_SIZE).getint();
                        if (nKeysCountSigned < 0) {
                            return set_error(serror, SCRIPT_ERR_PUBKEY_COUNT);
                        }

                        uint64_t nKeysCount = static_cast<uint64_t>(nKeysCountSigned);
                        if (nKeysCount > config.GetMaxPubKeysPerMultiSig(utxo_after_genesis, consensus)) {
                            return set_error(serror, SCRIPT_ERR_PUBKEY_COUNT);
                        }

                        nOpCount += nKeysCount;
                        if (!IsValidMaxOpsPerScript(nOpCount, config, utxo_after_genesis, consensus)) {
                            return set_error(serror, SCRIPT_ERR_OP_COUNT);
                        }
                        uint64_t ikey = ++i;
                        // ikey2 is the position of last non-signature item in
                        // the stack. Top stack item = 1. With
                        // SCRIPT_VERIFY_NULLFAIL, this is used for cleanup if
                        // operation fails.
                        uint64_t ikey2 = nKeysCount + 2;
                        i += nKeysCount;
                        if (stack.size() < i) {
                            return set_error(
                                serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        }

                        int64_t nSigsCountSigned =
                            CScriptNum(stack.stacktop(-i).GetElement(), fRequireMinimal, CScriptNum::MAXIMUM_ELEMENT_SIZE).getint();

                        if (nSigsCountSigned < 0) {
                            return set_error(serror, SCRIPT_ERR_SIG_COUNT);
                        }
                        uint64_t nSigsCount = static_cast<uint64_t>(nSigsCountSigned);
                        if (nSigsCount > nKeysCount) {
                            return set_error(serror, SCRIPT_ERR_SIG_COUNT);
                        }

                        uint64_t isig = ++i;
                        i += nSigsCount;
                        if (stack.size() < i) {
                            return set_error(
                                serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        }

                        // Subset of script starting at the most recent
                        // codeseparator
                        CScript scriptCode(pbegincodehash, pend);

                        // Remove signature for pre-fork scripts
                        for (uint64_t k = 0; k < nSigsCount; k++) {
                            LimitedVector &vchSig = stack.stacktop(-isig - k);
                            CleanupScriptCode(scriptCode, vchSig.GetElement(), flags);
                        }

                        bool fSuccess = true;
                        while (fSuccess && nSigsCount > 0) {
                            if (token.IsCanceled())
                            {
                                return {};
                            }

                            LimitedVector &vchSig = stack.stacktop(-isig);
                            LimitedVector &vchPubKey = stack.stacktop(-ikey);

                            // Note how this makes the exact order of
                            // pubkey/signature evaluation distinguishable by
                            // CHECKMULTISIG NOT if the STRICTENC flag is set.
                            // See the script_(in)valid tests for details.

                            if (!CheckSignatureEncoding(vchSig.GetElement(), flags, serror) ||
                                !CheckPubKeyEncoding(vchPubKey.GetElement(), flags, serror)) {
                                // serror is set
                                return false;
                            }

                            // Check signature
                            bool fOk = checker.CheckSig(vchSig.GetElement(), vchPubKey.GetElement(),
                                                        scriptCode, flags & SCRIPT_ENABLE_SIGHASH_FORKID);

                            if (fOk) {
                                isig++;
                                nSigsCount--;
                            }
                            ikey++;
                            nKeysCount--;

                            // If there are more signatures left than keys left,
                            // then too many signatures have failed. Exit early,
                            // without checking any further signatures.
                            if (nSigsCount > nKeysCount) {
                                fSuccess = false;
                            }
                        }

                        // Clean up stack of actual arguments
                        while (i-- > 1) {
                            // If the operation failed, we require that all
                            // signatures must be empty vector
                            if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) &&
                                !ikey2 && stack.stacktop(-1).size()) {
                                return set_error(serror,
                                                 SCRIPT_ERR_SIG_NULLFAIL);
                            }
                            if (ikey2 > 0) {
                                ikey2--;
                            }
                            stack.pop_back();
                        }

                        // A bug causes CHECKMULTISIG to consume one extra
                        // argument whose contents were not checked in any way.
                        //
                        // Unfortunately this is a potential source of
                        // mutability, so optionally verify it is exactly equal
                        // to zero prior to removing it from the stack.
                        if (stack.size() < 1) {
                            return set_error(
                                serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        }
                        if ((flags & SCRIPT_VERIFY_NULLDUMMY) &&
                            stack.stacktop(-1).size()) {
                            return set_error(serror, SCRIPT_ERR_SIG_NULLDUMMY);
                        }
                        stack.pop_back();

                        stack.push_back(fSuccess ? vchTrue : vchFalse);

                        if (opcode == OP_CHECKMULTISIGVERIFY) {
                            if (fSuccess) {
                                stack.pop_back();
                            } else {
                                return set_error(
                                    serror, SCRIPT_ERR_CHECKMULTISIGVERIFY);
                            }
                        }
                    } break;
                         */
                        break;
                    case OP_CHECKLOCKTIMEVERIFY:
                        if (!verifyFlags.contains(VerifyFlag.CHECKLOCKTIMEVERIFY)) {
                            // not enabled; treat as a NOP2
                            if (verifyFlags.contains(VerifyFlag.DISCOURAGE_UPGRADABLE_NOPS)) {
                                throw new ScriptException(ScriptError.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS, "Script used a reserved opcode " + opcode);
                            }
                            break;
                        }
                        executeCheckLockTimeVerify(txContainingThis, (int) index, stack, verifyFlags);
                        break;
                    case OP_CHECKSEQUENCEVERIFY:
                        if (!verifyFlags.contains(VerifyFlag.CHECKSEQUENCEVERIFY)) {
                            // not enabled; treat as a NOP3
                            if (verifyFlags.contains(VerifyFlag.DISCOURAGE_UPGRADABLE_NOPS)) {
                                throw new ScriptException(ScriptError.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS, "Script used a reserved opcode " + opcode);
                            }
                            break;
                        }
                        executeCheckSequenceVerify(txContainingThis, (int) index, stack, verifyFlags);
                        break;
                    case OP_NOP1:
                    case OP_NOP4:
                    case OP_NOP5:
                    case OP_NOP6:
                    case OP_NOP7:
                    case OP_NOP8:
                    case OP_NOP9:
                    case OP_NOP10:
                        if (verifyFlags.contains(VerifyFlag.DISCOURAGE_UPGRADABLE_NOPS)) {
                            throw new ScriptException(ScriptError.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS, "Script used a reserved opcode " + opcode);
                        }
                        break;

                    default:
                        throw new ScriptException(ScriptError.SCRIPT_ERR_BAD_OPCODE, "Script used a reserved or disabled opcode: " + opcode);
                }
            }

            if (stack.size() + altstack.size() > MAX_STACK_SIZE || stack.size() + altstack.size() < 0)
                throw new ScriptException(ScriptError.SCRIPT_ERR_STACK_SIZE, "Stack size exceeded range");
        }

        if (!ifStack.isEmpty())
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "OP_IF/OP_NOTIF without OP_ENDIF");
    }


    // This is more or less a direct translation of the code in Bitcoin Core
    private static void executeCheckLockTimeVerify(Transaction txContainingThis, int index, LinkedList<byte[]> stack, Set<VerifyFlag> verifyFlags) throws ScriptException {
        if (stack.size() < 1)
            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_CHECKLOCKTIMEVERIFY on a stack with size < 1");

        // Thus as a special case we tell CScriptNum to accept up
        // to 5-byte bignums to avoid year 2038 issue.
        final BigInteger nLockTime = castToBigInteger(stack.getLast(), 5, verifyFlags.contains(VerifyFlag.MINIMALDATA));

        if (nLockTime.compareTo(BigInteger.ZERO) < 0)
            throw new ScriptException(ScriptError.SCRIPT_ERR_NEGATIVE_LOCKTIME, "Negative locktime");

        // There are two kinds of nLockTime, need to ensure we're comparing apples-to-apples
        if (!(
                ((txContainingThis.getLockTime() <  Transaction.LOCKTIME_THRESHOLD) && (nLockTime.compareTo(Transaction.LOCKTIME_THRESHOLD_BIG)) < 0) ||
                        ((txContainingThis.getLockTime() >= Transaction.LOCKTIME_THRESHOLD) && (nLockTime.compareTo(Transaction.LOCKTIME_THRESHOLD_BIG)) >= 0))
        )
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Locktime requirement type mismatch");

        // Now that we know we're comparing apples-to-apples, the
        // comparison is a simple numeric one.
        if (nLockTime.compareTo(BigInteger.valueOf(txContainingThis.getLockTime())) > 0)
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Locktime requirement not satisfied");

        // Finally the nLockTime feature can be disabled and thus
        // CHECKLOCKTIMEVERIFY bypassed if every txin has been
        // finalized by setting nSequence to maxint. The
        // transaction would be allowed into the blockchain, making
        // the opcode ineffective.
        //
        // Testing if this vin is not final is sufficient to
        // prevent this condition. Alternatively we could test all
        // inputs, but testing just this input minimizes the data
        // required to prove correct CHECKLOCKTIMEVERIFY execution.
        if (!txContainingThis.getInputs().get(index).isFinal())
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Transaction contains a final transaction input for a CHECKLOCKTIMEVERIFY script.");
    }

    private static void executeCheckSequenceVerify(Transaction txContainingThis, int index, LinkedList<byte[]> stack, Set<VerifyFlag> verifyFlags) throws ScriptException {
        if (stack.size() < 1)
            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_CHECKSEQUENCEVERIFY on a stack with size < 1");

        // Note that elsewhere numeric opcodes are limited to
        // operands in the range -2**31+1 to 2**31-1, however it is
        // legal for opcodes to produce results exceeding that
        // range. This limitation is implemented by CScriptNum's
        // default 4-byte limit.
        //
        // Thus as a special case we tell CScriptNum to accept up
        // to 5-byte bignums, which are good until 2**39-1, well
        // beyond the 2**32-1 limit of the nSequence field itself.
        final long nSequence = castToBigInteger(stack.getLast(), 5, verifyFlags.contains(VerifyFlag.MINIMALDATA)).longValue();

        // In the rare event that the argument may be < 0 due to
        // some arithmetic being done first, you can always use
        // 0 MAX CHECKSEQUENCEVERIFY.
        if (nSequence < 0)
            throw new ScriptException(ScriptError.SCRIPT_ERR_NEGATIVE_LOCKTIME, "Negative sequence");

        // To provide for future soft-fork extensibility, if the
        // operand has the disabled lock-time flag set,
        // CHECKSEQUENCEVERIFY behaves as a NOP.
        if ((nSequence & ScriptFlags.SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0)
            return;

        // Compare the specified sequence number with the input.
        checkSequence(nSequence, txContainingThis, index);
    }

    private static void checkSequence(long nSequence, Transaction txContainingThis, int index) {
        // Relative lock times are supported by comparing the passed
        // in operand to the sequence number of the input.
        long txToSequence = txContainingThis.getInputs().get(index).getSequenceNumber();

        // Fail if the transaction's version number is not set high
        // enough to trigger BIP 68 rules.
        if (txContainingThis.getVersion() < 2)
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Transaction version is < 2");

        // Sequence numbers with their most significant bit set are not
        // consensus constrained. Testing that the transaction's sequence
        // number do not have this bit set prevents using this property
        // to get around a CHECKSEQUENCEVERIFY check.
        if ((txToSequence & ScriptFlags.SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0)
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Sequence disable flag is set");

        // Mask off any bits that do not have consensus-enforced meaning
        // before doing the integer comparisons
        long nLockTimeMask =  ScriptFlags.SEQUENCE_LOCKTIME_TYPE_FLAG | ScriptFlags.SEQUENCE_LOCKTIME_MASK;
        long txToSequenceMasked = txToSequence & nLockTimeMask;
        long nSequenceMasked = nSequence & nLockTimeMask;

        // There are two kinds of nSequence: lock-by-blockheight
        // and lock-by-blocktime, distinguished by whether
        // nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG.
        //
        // We want to compare apples to apples, so fail the script
        // unless the type of nSequenceMasked being tested is the same as
        // the nSequenceMasked in the transaction.
        if (!((txToSequenceMasked < ScriptFlags.SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked < ScriptFlags.SEQUENCE_LOCKTIME_TYPE_FLAG) ||
                (txToSequenceMasked >= ScriptFlags.SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked >= ScriptFlags.SEQUENCE_LOCKTIME_TYPE_FLAG))) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Relative locktime requirement type mismatch");
        }

        // Now that we know we're comparing apples-to-apples, the
        // comparison is a simple numeric one.
        if (nSequenceMasked > txToSequenceMasked)
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Relative locktime requirement not satisfied");
    }


}
