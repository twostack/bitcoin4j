/*
 * Copyright 2011 Google Inc.
 * Copyright 2012 Matt Corallo.
 * Copyright 2014 Andreas Schildbach
 * Copyright 2017 Nicola Atzei
 * Copyright 2021 Stephan M. February
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.twostack.bitcoin4j.script;

import at.favre.lib.bytes.Bytes;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.twostack.bitcoin4j.*;
import org.twostack.bitcoin4j.exception.ProtocolException;
import org.twostack.bitcoin4j.transaction.*;

import javax.annotation.Nullable;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static com.google.common.base.Preconditions.checkArgument;
import static org.twostack.bitcoin4j.script.Script.*;
import static org.twostack.bitcoin4j.script.ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION;
import static org.twostack.bitcoin4j.script.ScriptOpCodes.*;

public class Interpreter {

    private static final Logger log = LoggerFactory.getLogger(Script.class);

//    public static final long MAX_SCRIPT_ELEMENT_SIZE = 520;  // bytes
    public static final long MAX_SCRIPT_ELEMENT_SIZE = 2147483647;  // 2Gigabytes after Genesis - (2^31 -1)
    private static final int MAX_OPS_PER_SCRIPT = 201;
    private static final int MAX_STACK_SIZE = 1000;
    private static final int DEFAULT_MAX_NUM_ELEMENT_SIZE = 4;
    private static final int MAX_PUBKEYS_PER_MULTISIG = 20;
    private static final int MAX_SCRIPT_SIZE = 10000;
    public static final int SIG_SIZE = 75;
    /** Max number of sigops allowed in a standard p2sh redeem script */
    public static final int MAX_P2SH_SIGOPS = 15;
    public static final int DEFAULT_SCRIPT_NUM_LENGTH_POLICY_AFTER_GENESIS = 250 * 1024;

    public static final int MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS = 520;

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
     * the normal maximum length does not apply (i.e. CHECKLOCKTIMEVERIFY).
     *
     * @param maxLength the maximum length in bytes.
     * @param requireMinimal check if the number is encoded with the minimum possible number of bytes
     * @throws ScriptException if the chunk is longer than the specified maximum.
     */
    /* package private */ static BigInteger castToBigInteger(final byte[] chunk, final int maxLength, final boolean requireMinimal) throws ScriptException {
        if (chunk.length > maxLength)
            throw new ScriptException(ScriptError.SCRIPT_ERR_NUMBER_OVERFLOW, "Script attempted to use an integer larger than " + maxLength + " bytes");

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
                    throw  new ScriptException(ScriptError.SCRIPT_ERR_NUMBER_MINENCODE, "non-minimally encoded script number");
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


    private static boolean isOpcodeDisabled(int opcode, Set<VerifyFlag> verifyFlags) {


        switch (opcode) {
            case OP_2MUL:
            case OP_2DIV:
                //disabled codes
                return true;

            default:
                //not an opcode that was ever disabled
                break;
        }



        return false;

    }


//    /**
//     * Exposes the script interpreter.
//     * is useful if you need more precise control or access to the final state of the stack. This interface is very
//     * likely to change in future.
//     */
//    public static void executeScript(@Nullable Transaction txContainingThis, long index,
//                                     Script script, LinkedList<byte[]> stack, Coin value, Set<VerifyFlag> verifyFlags) throws ScriptException {
//        executeScript(txContainingThis,index, script, stack, value, verifyFlags /*, null*/);
//    }


    /**
     * Exposes the script interpreter. Normally you should not use this directly, instead use
     * is useful if you need more precise control or access to the final state of the stack. This interface is very
     * likely to change in future.
     */
    public static void executeScript(@Nullable Transaction txContainingThis, long index,
                                     Script script, LinkedList<byte[]> stack, Coin value, Set<VerifyFlag> verifyFlags /*, ScriptStateListener scriptStateListener*/) throws ScriptException {
        int opCount = 0;
        int lastCodeSepLocation = 0;
        final boolean enforceMinimal = verifyFlags.contains(VerifyFlag.MINIMALDATA);

        LinkedList<byte[]> altstack = new LinkedList<>();
        LinkedList<Boolean> ifStack = new LinkedList<>();
        LinkedList<Boolean> elseStack = new LinkedList<>();
        boolean nonTopLevelReturnAfterGenesis = false;

        int nextLocationInScript = 0;
        for (ScriptChunk chunk : script.chunks) {
            int opcode = chunk.opcode;

            // Do not execute instructions if Genesis OP_RETURN was found in executed branches.
            boolean shouldExecute = !ifStack.contains(false) && (!nonTopLevelReturnAfterGenesis || opcode == OP_RETURN);
            nextLocationInScript += chunk.size();

            // Check stack element size
            if (chunk.data != null && (!verifyFlags.contains(VerifyFlag.UTXO_AFTER_GENESIS) && chunk.data.length > MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS))
                throw new ScriptException(ScriptError.SCRIPT_ERR_PUSH_SIZE, "Attempted to push a data string larger than 520 bytes");

            // Note how OP_RESERVED does not count towards the opcode limit.
            if (opcode > OP_16) {
                opCount++;
                if (opCount > DEFAULT_SCRIPT_NUM_LENGTH_POLICY_AFTER_GENESIS)
                    throw new ScriptException(ScriptError.SCRIPT_ERR_OP_COUNT, "More script operations than is allowed");
            }

            // Disabled opcodes.
            if (isOpcodeDisabled(opcode, verifyFlags) && (!verifyFlags.contains(VerifyFlag.UTXO_AFTER_GENESIS) || shouldExecute)){
                throw new ScriptException(ScriptError.SCRIPT_ERR_DISABLED_OPCODE, "Script included a disabled Script Op.");
            }

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
                    case OP_NOTIF:
                        boolean fValue = false;
                        if (shouldExecute){
                            if (stack.size() < 1){
                                throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "Attempted OP_IF on an empty stack");
                            }

                            byte[] stacktop = stack.getLast();
                            if (verifyFlags.contains(VerifyFlag.MINIMALIF)) {
                                if (stacktop.length > 1){
                                    throw new ScriptException(ScriptError.SCRIPT_ERR_MINIMALIF, "Argument for OP_IF/NOT_IF must be 0x01 or empty");
                                }

                                if (stacktop.length == 1 && stacktop[0] != 1){
                                    throw new ScriptException(ScriptError.SCRIPT_ERR_MINIMALIF, "Argument for OP_IF/NOT_IF must be 0x01 or empty");
                                }
                            }

                            fValue = castToBool(stacktop);
                            if (opcode == OP_NOTIF){
                                fValue = !fValue;
                            }
                            stack.pollLast(); //pop top value off stack
                        }
                        ifStack.add(fValue);
                        elseStack.add(false);
                        continue;
                    case OP_ELSE:
                        //only one ELSE is allowed in IF after genesis
                        if (ifStack.isEmpty() || (!elseStack.isEmpty() && elseStack.getLast() && verifyFlags.contains(VerifyFlag.UTXO_AFTER_GENESIS)))
                            throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "Attempted OP_ELSE without OP_IF/NOTIF");
                        ifStack.add(!ifStack.pollLast());
                        elseStack.set(elseStack.size() - 1, true);
                        continue;
                    case OP_ENDIF:
                        if (ifStack.isEmpty())
                            throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "Attempted OP_ENDIF without OP_IF/NOTIF");
                        ifStack.pollLast();
                        elseStack.pollLast();
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
                        stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.valueOf(Script.decodeFromOpN(opcode)), false)));
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
                        if (verifyFlags.contains(VerifyFlag.UTXO_AFTER_GENESIS)){
                            if (ifStack.isEmpty()){
                                // Terminate the execution as successful. The remainder of the script does not affect the validity (even in
                                // presence of unbalanced IFs, invalid opcodes etc)
                                return;
                            }
                            nonTopLevelReturnAfterGenesis = true;
                        }else {
                            // Pre-Genesis OP_RETURN marks script as invalid
                            throw new ScriptException(ScriptError.SCRIPT_ERR_OP_RETURN, "Script called OP_RETURN");
                        }
                        break;

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


                    case OP_CAT:
                        if (stack.size() < 2)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Invalid stack operation.");
                        byte[] catBytes2 = stack.pollLast();
                        byte[] catBytes1 = stack.pollLast();

                        int len = catBytes1.length + catBytes2.length;
                        if (!verifyFlags.contains(VerifyFlag.UTXO_AFTER_GENESIS) && len > MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS)
                            throw new ScriptException(ScriptError.SCRIPT_ERR_PUSH_SIZE, "Push value size limit exceeded.");

                        byte[] catOut = new byte[len];
                        System.arraycopy(catBytes1, 0, catOut, 0, catBytes1.length);
                        System.arraycopy(catBytes2, 0, catOut, catBytes1.length, catBytes2.length);
                        stack.addLast(catOut);

                        break;

                    case OP_NUM2BIN:
                        if (stack.size() < 2)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Invalid stack operation.");

                        int numSize = castToBigInteger(stack.pollLast(), enforceMinimal).intValue();

                        if (!verifyFlags.contains(VerifyFlag.UTXO_AFTER_GENESIS) && numSize > MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS)
                            throw new ScriptException(ScriptError.SCRIPT_ERR_PUSH_SIZE, "Push value size limit exceeded.");

                        byte[] rawNumBytes = stack.pollLast();

                        // Try to see if we can fit that number in the number of
                        // byte requested.
                        byte[] minimalNumBytes = Utils.minimallyEncodeLE(rawNumBytes);
                        if (minimalNumBytes.length > numSize) {
                            //we can't
                            throw new ScriptException(ScriptError.SCRIPT_ERR_PUSH_SIZE, "The requested encoding is impossible to satisfy.");
                        }

                        if (minimalNumBytes.length == numSize) {
                            //already the right size so just push it to stack
                            stack.addLast(minimalNumBytes);
                        } else if (numSize == 0) {
                            stack.addLast(Utils.EMPTY_BYTE_ARRAY);
                        } else {
                            int signBit = 0x00;
                            if (minimalNumBytes.length > 0) {
                                signBit = minimalNumBytes[minimalNumBytes.length - 1] & 0x80;
                                minimalNumBytes[minimalNumBytes.length - 1] &= 0x7f;
                            }
                            int minimalBytesToCopy = minimalNumBytes.length > numSize ? numSize : minimalNumBytes.length;
                            byte[] expandedNumBytes = new byte[numSize]; //initialized to all zeroes
                            System.arraycopy(minimalNumBytes, 0, expandedNumBytes, 0, minimalBytesToCopy);
                            expandedNumBytes[expandedNumBytes.length - 1] = (byte) signBit;
                            stack.addLast(expandedNumBytes);
                        }
                        break;

                    case OP_SPLIT:
                        if (stack.size() < 2)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Invalid stack operation.");

                        BigInteger biSplitPos = castToBigInteger(stack.pollLast(), enforceMinimal);

                        //sanity check in case we aren't enforcing minimal number encoding
                        //we will check that the biSplitPos value can be safely held in an int
                        //before we cast it as BigInteger will behave similar to casting if the value
                        //is greater than the target type can hold.
                        BigInteger biMaxInt = BigInteger.valueOf((long) Integer.MAX_VALUE);
                        if (biSplitPos.compareTo(biMaxInt) >= 0)
                            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Invalid OP_SPLIT range.");

                        int splitPos = biSplitPos.intValue();
                        byte[] splitBytes = stack.pollLast();

                        if (splitPos > splitBytes.length || splitPos < 0)
                            throw new ScriptException(ScriptError.SCRIPT_ERR_SPLIT_RANGE, "Invalid OP_SPLIT range.");

                        byte[] splitOut1 = new byte[splitPos];
                        byte[] splitOut2 = new byte[splitBytes.length - splitPos];

                        System.arraycopy(splitBytes, 0, splitOut1, 0, splitPos);
                        System.arraycopy(splitBytes, splitPos, splitOut2, 0, splitOut2.length);

                        stack.addLast(splitOut1);
                        stack.addLast(splitOut2);
                        break;

                    case OP_BIN2NUM:
                        if (stack.size() < 1)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Invalid stack operation.");

                        byte[] binBytes = stack.pollLast();
                        byte[] numBytes = Utils.minimallyEncodeLE(binBytes);

                        if (!Utils.checkMinimallyEncodedLE(numBytes, DEFAULT_MAX_NUM_ELEMENT_SIZE))
                            throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_NUMBER_RANGE, "Given operand is not a number within the valid range [-2^31...2^31]");

                        stack.addLast(numBytes);

                        break;
                    case OP_SIZE:
                        if (stack.size() < 1)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_SIZE on an empty stack");
                        stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.valueOf(stack.getLast().length), false)));
                        break;

                    case OP_LSHIFT:
                    case OP_RSHIFT:

                        if (stack.size() < 2)
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Too few items on stack for SHIFT Op");

                        byte[] shiftCountBuf = stack.getLast();
                        byte[] valueToShiftBuf = stack.get(stack.size() - 2);

                        if (valueToShiftBuf.length == 0) {
                            stack.pop();
                        } else {
                            final BigInteger shiftCount = castToBigInteger(shiftCountBuf, 5, verifyFlags.contains(VerifyFlag.MINIMALDATA));

                            int n = shiftCount.intValue();
                            if (n < 0)
                                throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_NUMBER_RANGE, "Can't shift negative number of bits (n < 0)");

                            stack.pop();
                            stack.pop();

                            //using the Bytes lib. In-place byte-ops.
                            Bytes shifted = Bytes.wrap(valueToShiftBuf, ByteOrder.BIG_ENDIAN);

                            // bitcoin client implementation of l/rshift is unconventional, therefore this implementation is a bit unconventional
                            // bn library has shift functions however it expands the carried bits into a  byte
                            // in contrast to the bitcoin client implementation which drops off the carried bits
                            // in other words, if operand was 1 byte then we put 1 byte back on the stack instead of expanding to more shifted bytes
                            if (opcode == ScriptOpCodes.OP_LSHIFT) {
                                //Dart BigInt automagically right-pads the shifted bits
                                shifted = shifted.leftShift(n);
                            }
                            if (opcode == ScriptOpCodes.OP_RSHIFT) {
                                shifted = shifted.rightShift(n);
                            }

                            if (n > 0){
                                //shift occured
                                stack.push(shifted.array());

                            }else{
                                //no shift, just push original value back onto stack
                                stack.push(valueToShiftBuf);
                            }

                        }
                        break;
                    case OP_INVERT: {
                        if (stack.size() < 1) {
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "No elements left on stack.");
                        }
                        byte[] vch1 = stack.pollLast();
                        // To avoid allocating, we modify vch1 in place
                        for (int i = 0; i < vch1.length; i++) {
                            vch1[i] = (byte) (~vch1[i] & 0xFF);
                        }
                        stack.push(vch1);

                        break;
                    }
                    case OP_AND:
                    case OP_OR:
                    case OP_XOR:
                        // (x1 x2 - out)
                        if (stack.size() < 2) {
                            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Invalid stack operation.");
                        }

                        //valtype &vch2 = stacktop(-1);
                        //valtype &vch1 = stacktop(-2);
                        byte[] vch2 = stack.pollLast();
                        byte[] vch1 = stack.pollLast();

                        // Inputs must be the same size
                        if (vch1.length != vch2.length) {
                            throw new ScriptException(ScriptError.SCRIPT_ERR_OPERAND_SIZE, "Invalid operand size.");
                        }

                        // To avoid allocating, we modify vch1 in place.
                        switch (opcode) {
                            case OP_AND:
                                for (int i = 0; i < vch1.length; i++) {
                                    vch1[i] &= vch2[i];
                                }
                                break;
                            case OP_OR:
                                for (int i = 0; i < vch1.length; i++) {
                                    vch1[i] |= vch2[i];
                                }
                                break;
                            case OP_XOR:
                                for (int i = 0; i < vch1.length; i++) {
                                    vch1[i] ^= vch2[i];
                                }
                                break;
                            default:
                                break;
                        }

                        // And pop vch2.
                        //popstack(stack);

                        //put vch1 back on stack
                        stack.addLast(vch1);

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
                    case OP_DIV:
                    case OP_MUL:
                    case OP_MOD:
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

                            case OP_MUL:
                                numericOPresult = numericOPnum1.multiply(numericOPnum2);
                                break;

                            case OP_DIV:
                                if (numericOPnum2.intValue() == 0)
                                    throw new ScriptException(ScriptError.SCRIPT_ERR_DIV_BY_ZERO, "Division by zero error");
                                numericOPresult = numericOPnum1.divide(numericOPnum2);
                                break;

                            case OP_MOD:
                                if (numericOPnum2.intValue() == 0)
                                    throw new ScriptException(ScriptError.SCRIPT_ERR_MOD_BY_ZERO, "Modulo by zero error");

                                /**
                                 * BigInteger doesn't behave the way we want for modulo operations.  Firstly it's
                                 * always garunteed to return a +ve result.  Secondly it will throw an exception
                                 * if the 2nd operand is negative.  So we'll convert the values to longs and use native
                                 * modulo.  When we expand the number limits to arbitrary length we will likely need
                                 * a new BigNum implementation to handle this correctly.
                                 */
                                long lOp1 = numericOPnum1.longValue();
                                if (!BigInteger.valueOf(lOp1).equals(numericOPnum1)) {
                                    //in case the value is larger than a long can handle we need to crash and burn.
                                    throw new RuntimeException("Cannot handle large negative operand for modulo operation");
                                }
                                long lOp2 = numericOPnum2.longValue();
                                if (!BigInteger.valueOf(lOp2).equals(numericOPnum2)) {
                                    //in case the value is larger than a long can handle we need to crash and burn.
                                    throw new RuntimeException("Cannot handle large negative operand for modulo operation");
                                }
                                long lOpResult = lOp1 % lOp2;
                                numericOPresult = BigInteger.valueOf(lOpResult);

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
                        executeCheckSig(txContainingThis, (int) index, script, stack, lastCodeSepLocation, opcode, value, verifyFlags);
                        break;

                    case OP_CHECKMULTISIG:
                    case OP_CHECKMULTISIGVERIFY:
                        if (txContainingThis == null)
                            throw new IllegalStateException("Script attempted signature check but no tx was provided");
                        opCount = executeMultiSig(txContainingThis, (int) index, script, stack, opCount, lastCodeSepLocation, opcode, value, verifyFlags);
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
                        if (isInvalidBranchingOpcode(opcode) && verifyFlags.contains(VerifyFlag.UTXO_AFTER_GENESIS) && !shouldExecute){
                            break;
                        }
                        throw new ScriptException(ScriptError.SCRIPT_ERR_BAD_OPCODE, "Script used a reserved or disabled opcode: " + opcode);
                }
            }

            if (stack.size() + altstack.size() > MAX_STACK_SIZE || stack.size() + altstack.size() < 0)
                throw new ScriptException(ScriptError.SCRIPT_ERR_STACK_SIZE, "Stack size exceeded range");
        }

        if (!ifStack.isEmpty())
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "OP_IF/OP_NOTIF without OP_ENDIF");
    }

    private static boolean isInvalidBranchingOpcode(int opcode) {
        return opcode == OP_VERIF || opcode == OP_VERNOTIF;
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


    public void correctlySpends( Script scriptSig, Script scriptPubKey, Transaction txn, int scriptSigIndex, Set<VerifyFlag> verifyFlags) throws ScriptException {
        correctlySpends(scriptSig, scriptPubKey, txn, scriptSigIndex,  verifyFlags, Coin.ZERO);
    }

    /**
     * Verifies that this script (interpreted as a scriptSig) correctly spends the given scriptPubKey.
     * TODO: Verify why I'd need to pass in scriptSig again if I already have it from the [txn] + [scriptSigIndex] parameter
     *
     * @param scriptSig the spending Script
     * @param scriptSigIndex The index in the provided txn of the scriptSig
     * @param txn The transaction in which the provided scriptSig resides.
     *            Accessing txn from another thread while this method runs results in undefined behavior.
     * @param scriptPubKey The connected scriptPubKey (in output ) containing the conditions needed to claim the value.
     * @param verifyFlags Each flag enables one validation rule.
     * @param satoshis Value of the input ? Needed for verification when ForkId sighash is used
     */
    public void correctlySpends( Script scriptSig, Script scriptPubKey, Transaction txn, int scriptSigIndex, Set<VerifyFlag> verifyFlags, Coin satoshis) throws ScriptException {
//    public void correctlySpends(Transaction txn, long scriptSigIndex, Script scriptPubKey, Coin value, Set<VerifyFlag> verifyFlags) throws ScriptException {
        // Clone the transaction because executing the script involves editing it, and if we die, we'll leave
        // the tx half broken (also it's not so thread safe to work on it directly.

        if (verifyFlags.contains(VerifyFlag.SIGPUSHONLY) && !Script.isPushOnly(scriptSig)){
           throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_PUSHONLY, "No pushdata operations allowed in scriptSig");
        }

        Transaction transaction;
        try {
            transaction = new Transaction(ByteBuffer.wrap(txn.serialize()));
        } catch (ProtocolException | IOException e) {
            throw new RuntimeException(e);   // Should not happen unless we were given a totally broken transaction.
        }
        if (scriptSig.getProgram().length > 10000 || scriptPubKey.getProgram().length > 10000)
            throw new ScriptException(ScriptError.SCRIPT_ERR_SCRIPT_SIZE, "Script larger than 10,000 bytes");

        LinkedList<byte[]> stack = new LinkedList<byte[]>();
        LinkedList<byte[]> p2shStack = null;

        //Q: Do we run the scriptSig to prime the stack, then run the scriptIndex ?
        executeScript(transaction, scriptSigIndex, scriptSig,  stack, satoshis, verifyFlags);
        if (verifyFlags.contains(VerifyFlag.P2SH))
            p2shStack = new LinkedList<byte[]>(stack);

        executeScript(transaction, scriptSigIndex, scriptPubKey, stack, satoshis, verifyFlags);

        if (stack.size() == 0)
            throw new ScriptException(ScriptError.SCRIPT_ERR_EVAL_FALSE, "Stack empty at end of script execution.");

        if (!castToBool(stack.pollLast()))
            throw new ScriptException(ScriptError.SCRIPT_ERR_EVAL_FALSE, "Script resulted in a non-true stack: " + stack);

        // P2SH is pay to script hash. It means that the scriptPubKey has a special form which is a valid
        // program but it has "useless" form that if evaluated as a normal program always returns true.
        // Instead, miners recognize it as special based on its template - it provides a hash of the real scriptPubKey
        // and that must be provided by the input. The goal of this bizarre arrangement is twofold:
        //
        // (1) You can sum up a large, complex script (like a CHECKMULTISIG script) with an address that's the same
        //     size as a regular address. This means it doesn't overload scannable QR codes/NFC tags or become
        //     un-wieldy to copy/paste.
        // (2) It allows the working set to be smaller: nodes perform best when they can store as many unspent outputs
        //     in RAM as possible, so if the outputs are made smaller and the inputs get bigger, then it's better for
        //     overall scalability and performance.

        // TODO: Check if we can take out enforceP2SH if there's a checkpoint at the enforcement block.
        if (verifyFlags.contains(VerifyFlag.P2SH) && ScriptPattern.isP2SH(scriptPubKey)) {
            for (ScriptChunk chunk : scriptSig.getChunks())
                if (chunk.isOpCode() && chunk.opcode > OP_16)
                    throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_PUSHONLY, "Attempted to spend a P2SH scriptPubKey with a script that contained script ops");

            byte[] scriptPubKeyBytes = p2shStack.pollLast();
            Script scriptPubKeyP2SH = new Script(scriptPubKeyBytes);

            executeScript(transaction, scriptSigIndex, scriptPubKeyP2SH, p2shStack, satoshis, verifyFlags);

            if (p2shStack.size() == 0)
                throw new ScriptException(ScriptError.SCRIPT_ERR_CLEANSTACK, "P2SH stack empty at end of script execution.");

            if (!castToBool(p2shStack.pollLast()))
                throw new ScriptException(ScriptError.SCRIPT_ERR_EVAL_FALSE, "P2SH script execution resulted in a non-true stack");
        }
    }


    private static void executeCheckSig(Transaction txContainingThis, int index, Script script, LinkedList<byte[]> stack,
                                        int lastCodeSepLocation, int opcode, Coin value,
                                        Set<VerifyFlag> verifyFlags) throws ScriptException {
        final boolean requireCanonical = verifyFlags.contains(VerifyFlag.STRICTENC)
                || verifyFlags.contains(VerifyFlag.DERSIG)
                || verifyFlags.contains(VerifyFlag.LOW_S);
        if (stack.size() < 2)
            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_CHECKSIG(VERIFY) on a stack with size < 2");
        byte[] pubKey = stack.pollLast();
        byte[] sigBytes = stack.pollLast();

        byte[] prog = script.getProgram();
        byte[] connectedScript = Arrays.copyOfRange(prog, lastCodeSepLocation, prog.length);

        UnsafeByteArrayOutputStream outStream = new UnsafeByteArrayOutputStream(sigBytes.length + 1);
        try {
            writeBytes(outStream, sigBytes);
        } catch (IOException e) {
            throw new RuntimeException(e); // Cannot happen
        }
        connectedScript = removeAllInstancesOf(connectedScript, outStream.toByteArray());

        // TODO: Use int for indexes everywhere, we can't have that many inputs/outputs
        boolean sigValid = false;
        try {
            TransactionSignature sig  = TransactionSignature.decodeFromBitcoin(sigBytes, requireCanonical, verifyFlags.contains(VerifyFlag.LOW_S));

            // TODO: Should check hash type is known
            SigHash sigHash = new SigHash();

            int sighashMode = sig.sigHashMode().value;
            if (sig.useForkId()) {
               sighashMode = sig.sigHashMode().value | SigHashType.FORKID.value;
            }

            byte[] hash = sigHash.createHash(txContainingThis, sig.sighashFlags, index, new Script(connectedScript), BigInteger.valueOf(value.value)); //FIXME: Use Coin instead ?
//            Sha256Hash hash = sig.useForkId() ?
//                    txContainingThis.hashForSignatureWitness(index, connectedScript, value, sig.sigHashMode(), sig.anyoneCanPay()) :
//                    txContainingThis.hashForSignature(index, connectedScript, (byte) sig.sighashFlags);
            sigValid = ECKey.verify(hash, sig, pubKey);
        } catch (Exception e1) {
            // There is (at least) one exception that could be hit here (EOFException, if the sig is too short)
            // Because I can't verify there aren't more, we use a very generic Exception catch

            // This RuntimeException occurs when signing as we run partial/invalid scripts to see if they need more
            // signing work to be done inside LocalTransactionSigner.signInputs.
            if (!e1.getMessage().contains("Reached past end of ASN.1 stream"))
                log.warn("Signature checking failed!", e1);
        }

        if (opcode == OP_CHECKSIG)
            stack.add(sigValid ? new byte[] {1} : new byte[] {});
        else if (opcode == OP_CHECKSIGVERIFY)
            if (!sigValid)
                throw new ScriptException(ScriptError.SCRIPT_ERR_CHECKSIGVERIFY, "Script failed OP_CHECKSIGVERIFY");
    }


    private static boolean isCanonicalPubkey(byte[] pubkey) {
        if (pubkey.length < 33) {
            //  Non-canonical public key: too short
            return false;
        }
        if (pubkey[0] == 0x04) {
            if (pubkey.length != 65) {
                //  Non-canonical public key: invalid length for uncompressed key
                return false;
            }
        } else if (pubkey[0] == 0x02 || pubkey[0] == 0x03) {
            if (pubkey.length != 33) {
                //  Non-canonical public key: invalid length for compressed key
                return false;
            }
        } else {
            //  Non-canonical public key: neither compressed nor uncompressed
            return false;
        }
        return true;
    }

    private static boolean isCompressedPubKey(byte[] pubKey) {
        if (pubKey.length != 33) {
            //  Non-canonical public key: invalid length for compressed key
            return false;
        }
        if (pubKey[0] != 0x02 && pubKey[0] != 0x03) {
            //  Non-canonical public key: invalid prefix for compressed key
            return false;
        }
        return true;
    }



    private static boolean checkPubKeyEncoding(byte[] pubKey, Set<VerifyFlag> flags) throws ScriptException{

       if (flags.contains(VerifyFlag.STRICTENC) && !isCanonicalPubkey(pubKey)) {
           throw new ScriptException(ScriptError.SCRIPT_ERR_PUBKEYTYPE, "Public key has invalid encoding");
       }

       if (flags.contains(VerifyFlag.COMPRESSED_PUBKEYTYPE) && !isCompressedPubKey(pubKey)){
           throw new ScriptException(ScriptError.SCRIPT_ERR_NONCOMPRESSED_PUBKEY, "Public key has invalid encoding");
       }

       return true;
    }


    private static int executeMultiSig(Transaction txContainingThis, int index, Script script, LinkedList<byte[]> stack,
                                       int opCount, int lastCodeSepLocation, int opcode, Coin value,
                                       Set<VerifyFlag> verifyFlags) throws ScriptException {
        final boolean requireCanonical = verifyFlags.contains(VerifyFlag.STRICTENC)
                || verifyFlags.contains(VerifyFlag.DERSIG)
                || verifyFlags.contains(VerifyFlag.LOW_S);
        final boolean enforceMinimal = verifyFlags.contains(VerifyFlag.MINIMALDATA);

        if (stack.size() < 1)
            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_CHECKMULTISIG(VERIFY) on a stack with size < 2");

        int pubKeyCount = castToBigInteger(stack.pollLast(), enforceMinimal).intValue();
        if (pubKeyCount < 0 || (!verifyFlags.contains(VerifyFlag.UTXO_AFTER_GENESIS) && pubKeyCount > 20)
                || (verifyFlags.contains(VerifyFlag.UTXO_AFTER_GENESIS) && pubKeyCount > Integer.MAX_VALUE))
            throw new ScriptException(ScriptError.SCRIPT_ERR_PUBKEY_COUNT, "OP_CHECKMULTISIG(VERIFY) with pubkey count out of range");
        opCount += pubKeyCount;
        if (opCount > DEFAULT_SCRIPT_NUM_LENGTH_POLICY_AFTER_GENESIS)
            throw new ScriptException(ScriptError.SCRIPT_ERR_CHECKMULTISIGVERIFY, "Total op (count > 250 * 1024) during OP_CHECKMULTISIG(VERIFY)");
        if (stack.size() < pubKeyCount + 1)
            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_CHECKMULTISIG(VERIFY) on a stack with size < num_of_pubkeys + 2");

        LinkedList<byte[]> pubkeys = new LinkedList<byte[]>();
        for (int i = 0; i < pubKeyCount; i++) {
            byte[] pubKey = stack.pollLast();
            pubkeys.add(pubKey);
        }

        int sigCount = castToBigInteger(stack.pollLast(), enforceMinimal).intValue();
        if (sigCount < 0 || sigCount > pubKeyCount)
            throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_COUNT, "OP_CHECKMULTISIG(VERIFY) with sig count out of range");
        if (stack.size() < sigCount + 1)
            throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_CHECKMULTISIG(VERIFY) on a stack with size < num_of_pubkeys + num_of_signatures + 3");

        LinkedList<byte[]> sigs = new LinkedList<byte[]>();
        for (int i = 0; i < sigCount; i++) {
            byte[] sig = stack.pollLast();
            sigs.add(sig);
        }

        byte[] prog = script.getProgram();
        byte[] connectedScript = Arrays.copyOfRange(prog, lastCodeSepLocation, prog.length);

        for (byte[] sig : sigs) {
            UnsafeByteArrayOutputStream outStream = new UnsafeByteArrayOutputStream(sig.length + 1);
            try {
                writeBytes(outStream, sig);
            } catch (IOException e) {
                throw new RuntimeException(e); // Cannot happen
            }
            connectedScript = removeAllInstancesOf(connectedScript, outStream.toByteArray());
        }

        boolean valid = true;
        while (sigs.size() > 0) {
            byte[] pubKey = pubkeys.pollFirst();
            // We could reasonably move this out of the loop, but because signature verification is significantly
            // more expensive than hashing, its not a big deal.

            //FIXME: Check Signature Encoding

            //CHECK Pubkey Encoding
            checkPubKeyEncoding(pubKey, verifyFlags);

            try {


                TransactionSignature sig = TransactionSignature.decodeFromBitcoin(sigs.getFirst(), requireCanonical, verifyFlags.contains(VerifyFlag.LOW_S));

                SigHash sigHash = new SigHash();

                int sighashMode = sig.sigHashMode().value;
                if (sig.useForkId()) {
                    sighashMode = sig.sigHashMode().value | SigHashType.FORKID.value;
                }

                byte[] hash = sigHash.createHash(txContainingThis, sighashMode, index, new Script(connectedScript), BigInteger.valueOf(value.value)); //FIXME: Use Coin instead ?
//                Sha256Hash hash = sig.useForkId() ?
//                        txContainingThis.hashForSignatureWitness(index, connectedScript, value, sig.sigHashMode(), sig.anyoneCanPay()):
//                        txContainingThis.hashForSignature(index, connectedScript, (byte) sig.sighashFlags);
                if (ECKey.verify(hash, sig, pubKey))
                    sigs.pollFirst();
            } catch (Exception e) {
                // There is (at least) one exception that could be hit here (EOFException, if the sig is too short)
                // Because I can't verify there aren't more, we use a very generic Exception catch
            }

            if (sigs.size() > pubkeys.size()) {
                valid = false;
                break;
            }
        }

        // We uselessly remove a stack object to emulate a Bitcoin Core bug.
        byte[] nullDummy = stack.pollLast();
        if (verifyFlags.contains(VerifyFlag.NULLDUMMY) && nullDummy.length > 0)
            throw new ScriptException(ScriptError.SCRIPT_ERR_CHECKMULTISIGVERIFY, "OP_CHECKMULTISIG(VERIFY) with non-null nulldummy: " + Arrays.toString(nullDummy));

        if (opcode == OP_CHECKMULTISIG) {
            stack.add(valid ? new byte[] {1} : new byte[] {});
        } else if (opcode == OP_CHECKMULTISIGVERIFY) {
            if (!valid)
                throw new ScriptException(ScriptError.SCRIPT_ERR_CHECKMULTISIGVERIFY, "Script failed OP_CHECKMULTISIGVERIFY");
        }
        return opCount;
    }


    private static void executeCheckSequenceVerify(Transaction txContainingThis, int index, LinkedList<byte[]> stack, Set<VerifyFlag> verifyFlags) throws ScriptException {
        if (stack.size() < 1)
            throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_CHECKSEQUENCEVERIFY on a stack with size < 1");

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
        if ((nSequence & TransactionInput.SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0)
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
        if ((txToSequence & TransactionInput.SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0)
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Sequence disable flag is set");

        // Mask off any bits that do not have consensus-enforced meaning
        // before doing the integer comparisons
        long nLockTimeMask =  TransactionInput.SEQUENCE_LOCKTIME_TYPE_FLAG | TransactionInput.SEQUENCE_LOCKTIME_MASK;
        long txToSequenceMasked = txToSequence & nLockTimeMask;
        long nSequenceMasked = nSequence & nLockTimeMask;

        // There are two kinds of nSequence: lock-by-blockheight
        // and lock-by-blocktime, distinguished by whether
        // nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG.
        //
        // We want to compare apples to apples, so fail the script
        // unless the type of nSequenceMasked being tested is the same as
        // the nSequenceMasked in the transaction.
        if (!((txToSequenceMasked < TransactionInput.SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked < TransactionInput.SEQUENCE_LOCKTIME_TYPE_FLAG) ||
                (txToSequenceMasked >= TransactionInput.SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked >= TransactionInput.SEQUENCE_LOCKTIME_TYPE_FLAG))) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Relative locktime requirement type mismatch");
        }

        // Now that we know we're comparing apples-to-apples, the
        // comparison is a simple numeric one.
        if (nSequenceMasked > txToSequenceMasked)
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Relative locktime requirement not satisfied");
    }
}
