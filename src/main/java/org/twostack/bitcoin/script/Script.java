/*
 * Copyright 2011 Google Inc.
 * Copyright 2012 Matt Corallo.
 * Copyright 2014 Andreas Schildbach
 * Copyright 2017 Nicola Atzei
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

package org.twostack.bitcoin.script;

import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.twostack.bitcoin.ECKey;
import org.twostack.bitcoin.Sha256Hash;
import org.twostack.bitcoin.UnsafeByteArrayOutputStream;
import org.twostack.bitcoin.Utils;
import org.twostack.bitcoin.address.Address;
import org.twostack.bitcoin.address.LegacyAddress;
import org.twostack.bitcoin.exception.ProtocolException;
import org.twostack.bitcoin.exception.SignatureDecodeException;
import org.twostack.bitcoin.exception.VerificationException;
import org.twostack.bitcoin.params.NetworkParameters;
import org.twostack.bitcoin.transaction.Transaction;
import org.twostack.bitcoin.transaction.TransactionInput;
import org.twostack.bitcoin.transaction.TransactionOutput;

import javax.annotation.Nullable;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static org.twostack.bitcoin.script.ScriptOpCodes.*;
import static com.google.common.base.Preconditions.*;

// TODO: Redesign this entire API to be more type safe and organised.

/**
 * <p>Programs embedded inside transactions that control redemption of payments.</p>
 *
 * <p>Bitcoin transactions don't specify what they do directly. Instead <a href="https://en.bitcoin.it/wiki/Script">a
 * small binary stack language</a> is used to define programs that when evaluated return whether the transaction
 * "accepts" or rejects the other transactions connected to it.</p>
 *
 * <p>In SPV mode, scripts are not run, because that would require all transactions to be available and lightweight
 * clients don't have that data. In full mode, this class is used to run the interpreted language. It also has
 * static methods for building scripts.</p>
 */
public class Script {

    /** Enumeration to encapsulate the type of this script. */
    public enum ScriptType {
        P2PKH(1), // pay to pubkey hash (aka pay to address)
        P2PK(2), // pay to pubkey
        P2SH(3); // pay to script hash

        public final int id;

        private ScriptType(int id) {
            this.id = id;
        }
    }

    /** Flags to pass to {Script#correctlySpends(Transaction, int, Coin, Script, Set)}.
     * Note currently only P2SH, DERSIG and NULLDUMMY are actually supported.
     */
    public enum VerifyFlag {
        P2SH, // Enable BIP16-style subscript evaluation.
        STRICTENC, // Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
        DERSIG, // Passing a non-strict-DER signature to a checksig operation causes script failure (softfork safe, BIP66 rule 1)
        LOW_S, // Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
        NULLDUMMY, // Verify dummy stack item consumed by CHECKMULTISIG is of zero-length.
        SIGPUSHONLY, // Using a non-push operator in the scriptSig causes script failure (softfork safe, BIP62 rule 2).
        MINIMALDATA, // Require minimal encodings for all push operations
        DISCOURAGE_UPGRADABLE_NOPS, // Discourage use of NOPs reserved for upgrades (NOP1-10)
        CLEANSTACK, // Require that only a single stack element remains after evaluation.
        CHECKLOCKTIMEVERIFY, // Enable CHECKLOCKTIMEVERIFY operation
        CHECKSEQUENCEVERIFY // Enable CHECKSEQUENCEVERIFY operation
    }
    public static final EnumSet<VerifyFlag> ALL_VERIFY_FLAGS = EnumSet.allOf(VerifyFlag.class);

    private static final Logger log = LoggerFactory.getLogger(Script.class);
    public static final long MAX_SCRIPT_ELEMENT_SIZE = 520;  // bytes
    private static final int MAX_OPS_PER_SCRIPT = 201;
    private static final int MAX_STACK_SIZE = 1000;
    private static final int MAX_PUBKEYS_PER_MULTISIG = 20;
    private static final int MAX_SCRIPT_SIZE = 10000;
    public static final int SIG_SIZE = 75;
    /** Max number of sigops allowed in a standard p2sh redeem script */
    public static final int MAX_P2SH_SIGOPS = 15;

    // The program is a set of chunks where each element is either [opcode] or [data, data, data ...]
    protected List<ScriptChunk> chunks;
    // Unfortunately, scripts are not ever re-serialized or canonicalized when used in signature hashing. Thus we
    // must preserve the exact bytes that we read off the wire, along with the parsed form.
    protected byte[] program;

    // Creation time of the associated keys in seconds since the epoch.
    private long creationTimeSeconds;

    /** Creates an empty script that serializes to nothing. */
    private Script() {
        chunks = new ArrayList<>();
    }

    // Used from ScriptBuilder.
    Script(List<ScriptChunk> chunks) {
        this.chunks = Collections.unmodifiableList(new ArrayList<>(chunks));
        creationTimeSeconds = Utils.currentTimeSeconds();
    }

    /**
     * Construct a Script that copies and wraps the programBytes array. The array is parsed and checked for syntactic
     * validity.
     * @param programBytes Array of program bytes from a transaction.
     */
    public Script(byte[] programBytes) throws ScriptException {
        program = programBytes;
        parse(programBytes);
        creationTimeSeconds = 0;
    }

    public static Script fromByteArray(byte[] programBytes) throws ScriptException{
        return new Script(programBytes, LocalDateTime.now().toEpochSecond(ZoneOffset.UTC));
    }

    public static Script fromString(String program) throws ScriptException{
        List<ScriptChunk> chunks = stringToChunks(program);

        return new Script(chunks);
    }

    public Script(byte[] programBytes, long creationTimeSeconds) throws ScriptException {
        program = programBytes;
        parse(programBytes);
        this.creationTimeSeconds = creationTimeSeconds;
    }

    public long getCreationTimeSeconds() {
        return creationTimeSeconds;
    }

    public void setCreationTimeSeconds(long creationTimeSeconds) {
        this.creationTimeSeconds = creationTimeSeconds;
    }

    /**
     * Returns the program opcodes as a string, for example "[1234] DUP HASH160", or "&lt;empty&gt;".
     */
    @Override
    public String toString() {
        if (!chunks.isEmpty())
            return Utils.SPACE_JOINER.join(chunks);
        else
            return "<empty>";
    }

    public String toAsmString(){
        if (!chunks.isEmpty()) {
            List<String> asmStrings = chunks.stream().map(chunk -> chunk.toEncodedString()).collect(Collectors.toList());
            return Utils.SPACE_JOINER.join(asmStrings);
        } else {
            return "<empty>";
        }
    }

    private static List<ScriptChunk> stringToChunks(String script) throws ScriptException{

        if (script.trim().isEmpty()) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Unexpected end of script");
        }

        List<ScriptChunk> _chunks = new ArrayList<ScriptChunk>();

        List<String> tokenList = Arrays.asList(script.split(" ")); //split on spaces
        tokenList.removeIf(token -> token.trim().isEmpty());

            //encode tokens, leaving non-token elements intact
        for (int index = 0; index < tokenList.size();) {
            String token = tokenList.get(index);

            String opcode = token;

            Integer opcodenum = ScriptOpCodes.getOpCode(opcode);

            if (opcodenum >= OP_2 && opcodenum <= OP_16) {
                opcodenum = Integer.valueOf(token);
                ScriptChunk newChunk = new ScriptChunk(opcodenum, Utils.HEX.decode(tokenList.get(index + 1).substring(2)));
                _chunks.add(newChunk);
                index = index + 2; //step by two
            } else if (opcodenum == ScriptOpCodes.OP_PUSHDATA1 ||
                    opcodenum == ScriptOpCodes.OP_PUSHDATA2 ||
                    opcodenum == ScriptOpCodes.OP_PUSHDATA4) {
                if (!tokenList.get(index + 2).substring(0, 2).equals("0x")) {
                    throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Pushdata data must start with 0x");
                }
                byte[] data = Utils.HEX.decode(tokenList.get(index + 2).substring(2));
                _chunks.add(new ScriptChunk(opcodenum, data));
                index = index + 3; //step by three
            } else {
                _chunks.add(new ScriptChunk(opcodenum, new byte[]{}));
                index = index + 1; //step by one
            }
        }

        return _chunks;
    }

    /** Returns the serialized program as a newly created byte array. */
    public byte[] getProgram() {
        try {
            //TODO: Investigate this. Failing to roundtrip might introduce problems
            // Don't round-trip as Bitcoin Core doesn't and it would introduce a mismatch.
            if (program != null)
                return Arrays.copyOf(program, program.length);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            for (ScriptChunk chunk : chunks) {
                chunk.write(bos);
            }
            program = bos.toByteArray();
            return program;
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /** Returns an immutable list of the scripts parsed form. Each chunk is either an opcode or data element. */
    public List<ScriptChunk> getChunks() {
        return Collections.unmodifiableList(chunks);
    }

    private static final ScriptChunk[] STANDARD_TRANSACTION_SCRIPT_CHUNKS = {
        new ScriptChunk(ScriptOpCodes.OP_DUP, null),
        new ScriptChunk(ScriptOpCodes.OP_HASH160, null),
        new ScriptChunk(ScriptOpCodes.OP_EQUALVERIFY, null),
        new ScriptChunk(ScriptOpCodes.OP_CHECKSIG, null),
    };

    /**
     * <p>To run a script, first we parse it which breaks it up into chunks representing pushes of data or logical
     * opcodes. Then we can run the parsed chunks.</p>
     *
     * <p>The reason for this split, instead of just interpreting directly, is to make it easier
     * to reach into a programs structure and pull out bits of data without having to run it.
     * This is necessary to render the to addresses of transactions in a user interface.
     * Bitcoin Core does something similar.</p>
     */
    private void parse(byte[] program) throws ScriptException {
        chunks = new ArrayList<>(5);   // Common size.
        ByteArrayInputStream bis = new ByteArrayInputStream(program);
        while (bis.available() > 0) {
            int opcode = bis.read();

            long dataToRead = -1;
            if (opcode >= 0 && opcode < OP_PUSHDATA1) {
                // Read some bytes of data, where how many is the opcode value itself.
                dataToRead = opcode;
            } else if (opcode == OP_PUSHDATA1) {
                if (bis.available() < 1) throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Unexpected end of script");
                dataToRead = bis.read();
            } else if (opcode == OP_PUSHDATA2) {
                // Read a short, then read that many bytes of data.
                if (bis.available() < 2) throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Unexpected end of script");
                dataToRead = Utils.readUint16FromStream(bis);
            } else if (opcode == OP_PUSHDATA4) {
                // Read a uint32, then read that many bytes of data.
                // Though this is allowed, because its value cannot be > 520, it should never actually be used
                if (bis.available() < 4) throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Unexpected end of script");
                dataToRead = Utils.readUint32FromStream(bis);
            }

            ScriptChunk chunk;
            if (dataToRead == -1) {
                chunk = new ScriptChunk(opcode, null);
            } else {
                if (dataToRead > bis.available())
                    throw new ScriptException(ScriptError.SCRIPT_ERR_BAD_OPCODE, "Push of data element that is larger than remaining data: " + dataToRead + " vs " + bis.available());
                byte[] data = new byte[(int)dataToRead];
                checkState(dataToRead == 0 || bis.read(data, 0, (int)dataToRead) == dataToRead);
                chunk = new ScriptChunk(opcode, data);
            }
            // Save some memory by eliminating redundant copies of the same chunk objects.
            for (ScriptChunk c : STANDARD_TRANSACTION_SCRIPT_CHUNKS) {
                if (c.equals(chunk)) chunk = c;
            }
            chunks.add(chunk);
        }
    }

    ////////////////////// Interface for writing scripts from scratch ////////////////////////////////

    /**
     * Writes out the given byte buffer to the output stream with the correct opcode prefix
     * To write an integer call writeBytes(out, Utils.reverseBytes(Utils.encodeMPI(val, false)));
     */
    public static void writeBytes(OutputStream os, byte[] buf) throws IOException {
        if (buf.length < OP_PUSHDATA1) {
            os.write(buf.length);
            os.write(buf);
        } else if (buf.length < 256) {
            os.write(OP_PUSHDATA1);
            os.write(buf.length);
            os.write(buf);
        } else if (buf.length < 65536) {
            os.write(OP_PUSHDATA2);
            Utils.uint16ToByteStreamLE(buf.length, os);
            os.write(buf);
        } else {
            throw new RuntimeException("Unimplemented");
        }
    }

    public static byte[] createInputScript(byte[] signature, byte[] pubkey) {
        try {
            // TODO: Do this by creating a Script *first* then having the script reassemble itself into bytes.
            ByteArrayOutputStream bits = new UnsafeByteArrayOutputStream(signature.length + pubkey.length + 2);
            writeBytes(bits, signature);
            writeBytes(bits, pubkey);
            return bits.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] createInputScript(byte[] signature) {
        try {
            // TODO: Do this by creating a Script *first* then having the script reassemble itself into bytes.
            ByteArrayOutputStream bits = new UnsafeByteArrayOutputStream(signature.length + 2);
            writeBytes(bits, signature);
            return bits.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    private int findKeyInRedeem(ECKey key) {
        checkArgument(chunks.get(0).isOpCode()); // P2SH scriptSig
        int numKeys = Script.decodeFromOpN(chunks.get(chunks.size() - 2).opcode);
        for (int i = 0 ; i < numKeys ; i++) {
            if (Arrays.equals(chunks.get(1 + i).data, key.getPubKey())) {
                return i;
            }
        }

        throw new IllegalStateException("Could not find matching key " + key.toString() + " in script " + this);
    }


    ////////////////////// Interface used during verification of transactions/blocks ////////////////////////////////

    private static int getSigOpCount(List<ScriptChunk> chunks, boolean accurate) throws ScriptException {
        int sigOps = 0;
        int lastOpCode = OP_INVALIDOPCODE;
        for (ScriptChunk chunk : chunks) {
            if (chunk.isOpCode()) {
                switch (chunk.opcode) {
                case OP_CHECKSIG:
                case OP_CHECKSIGVERIFY:
                    sigOps++;
                    break;
                case OP_CHECKMULTISIG:
                case OP_CHECKMULTISIGVERIFY:
                    if (accurate && lastOpCode >= OP_1 && lastOpCode <= OP_16)
                        sigOps += decodeFromOpN(lastOpCode);
                    else
                        sigOps += 20;
                    break;
                default:
                    break;
                }
                lastOpCode = chunk.opcode;
            }
        }
        return sigOps;
    }

    public static int decodeFromOpN(int opcode) {
        checkArgument((opcode == OP_0 || opcode == OP_1NEGATE) || (opcode >= OP_1 && opcode <= OP_16),
                "decodeFromOpN called on non OP_N opcode: %s", ScriptOpCodes.getOpCodeName(opcode));
        if (opcode == OP_0)
            return 0;
        else if (opcode == OP_1NEGATE)
            return -1;
        else
            return opcode + 1 - OP_1;
    }

    public static int encodeToOpN(int value) {
        checkArgument(value >= -1 && value <= 16, "encodeToOpN called for " + value + " which we cannot encode in an opcode.");
        if (value == 0)
            return OP_0;
        else if (value == -1)
            return OP_1NEGATE;
        else
            return value - 1 + OP_1;
    }


    private static boolean equalsRange(byte[] a, int start, byte[] b) {
        if (start + b.length > a.length)
            return false;
        for (int i = 0; i < b.length; i++)
            if (a[i + start] != b[i])
                return false;
        return true;
    }
    
    /**
     * Returns the script bytes of inputScript with all instances of the specified script object removed
     */
    public static byte[] removeAllInstancesOf(byte[] inputScript, byte[] chunkToRemove) {
        // We usually don't end up removing anything
        UnsafeByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(inputScript.length);

        int cursor = 0;
        while (cursor < inputScript.length) {
            boolean skip = equalsRange(inputScript, cursor, chunkToRemove);
            
            int opcode = inputScript[cursor++] & 0xFF;
            int additionalBytes = 0;
            if (opcode >= 0 && opcode < OP_PUSHDATA1) {
                additionalBytes = opcode;
            } else if (opcode == OP_PUSHDATA1) {
                additionalBytes = (0xFF & inputScript[cursor]) + 1;
            } else if (opcode == OP_PUSHDATA2) {
                additionalBytes = Utils.readUint16(inputScript, cursor) + 2;
            } else if (opcode == OP_PUSHDATA4) {
                additionalBytes = (int) Utils.readUint32(inputScript, cursor) + 4;
            }
            if (!skip) {
                try {
                    bos.write(opcode);
                    bos.write(Arrays.copyOfRange(inputScript, cursor, cursor + additionalBytes));
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
            cursor += additionalBytes;
        }
        return bos.toByteArray();
    }
    
    /**
     * Returns the script bytes of inputScript with all instances of the given op code removed
     */
    public static byte[] removeAllInstancesOfOp(byte[] inputScript, int opCode) {
        return removeAllInstancesOf(inputScript, new byte[] {(byte)opCode});
    }
    
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
    public boolean isOpReturn() {
        return ScriptPattern.isOpReturn(this);
    }

    /**
     * Exposes the script interpreter. Normally you should not use this directly, instead use
     * This method is useful if you need more precise control or access to the final state of
     * the stack. This interface is very likely to change in future.
     */
//    public static void executeScript(@Nullable Transaction txContainingThis, long index,
//                                     Script script, LinkedList<byte[]> stack, Set<VerifyFlag> verifyFlags) throws ScriptException {
//        int opCount = 0;
//        int lastCodeSepLocation = 0;
//
//        LinkedList<byte[]> altstack = new LinkedList<>();
//        LinkedList<Boolean> ifStack = new LinkedList<>();
//
//        int nextLocationInScript = 0;
//        for (ScriptChunk chunk : script.chunks) {
//            boolean shouldExecute = !ifStack.contains(false);
//            int opcode = chunk.opcode;
//            nextLocationInScript += chunk.size();
//
//            // Check stack element size
//            if (chunk.data != null && chunk.data.length > MAX_SCRIPT_ELEMENT_SIZE)
//                throw new ScriptException(ScriptError.SCRIPT_ERR_PUSH_SIZE, "Attempted to push a data string larger than 520 bytes");
//
//            // Note how OP_RESERVED does not count towards the opcode limit.
//            if (opcode > OP_16) {
//                opCount++;
//                if (opCount > MAX_OPS_PER_SCRIPT)
//                    throw new ScriptException(ScriptError.SCRIPT_ERR_OP_COUNT, "More script operations than is allowed");
//            }
//
//            // Disabled opcodes.
//            if (opcode == OP_CAT || opcode == OP_SUBSTR || opcode == OP_LEFT || opcode == OP_RIGHT ||
//                    opcode == OP_INVERT || opcode == OP_AND || opcode == OP_OR || opcode == OP_XOR ||
//                    opcode == OP_2MUL || opcode == OP_2DIV || opcode == OP_MUL || opcode == OP_DIV ||
//                    opcode == OP_MOD || opcode == OP_LSHIFT || opcode == OP_RSHIFT)
//                throw new ScriptException(ScriptError.SCRIPT_ERR_DISABLED_OPCODE, "Script included a disabled Script Op.");
//
//            if (shouldExecute && OP_0 <= opcode && opcode <= OP_PUSHDATA4) {
//                // Check minimal push
//                if (verifyFlags.contains(VerifyFlag.MINIMALDATA) && !chunk.isShortestPossiblePushData())
//                    throw new ScriptException(ScriptError.SCRIPT_ERR_MINIMALDATA, "Script included a not minimal push operation.");
//
//                if (opcode == OP_0)
//                    stack.add(new byte[]{});
//                else
//                    stack.add(chunk.data);
//            } else if (shouldExecute || (OP_IF <= opcode && opcode <= OP_ENDIF)){
//
//                switch (opcode) {
//                case OP_IF:
//                    if (!shouldExecute) {
//                        ifStack.add(false);
//                        continue;
//                    }
//                    if (stack.size() < 1)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "Attempted OP_IF on an empty stack");
//                    ifStack.add(castToBool(stack.pollLast()));
//                    continue;
//                case OP_NOTIF:
//                    if (!shouldExecute) {
//                        ifStack.add(false);
//                        continue;
//                    }
//                    if (stack.size() < 1)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "Attempted OP_NOTIF on an empty stack");
//                    ifStack.add(!castToBool(stack.pollLast()));
//                    continue;
//                case OP_ELSE:
//                    if (ifStack.isEmpty())
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "Attempted OP_ELSE without OP_IF/NOTIF");
//                    ifStack.add(!ifStack.pollLast());
//                    continue;
//                case OP_ENDIF:
//                    if (ifStack.isEmpty())
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "Attempted OP_ENDIF without OP_IF/NOTIF");
//                    ifStack.pollLast();
//                    continue;
//
//                // OP_0 is no opcode
//                case OP_1NEGATE:
//                    stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.ONE.negate(), false)));
//                    break;
//                case OP_1:
//                case OP_2:
//                case OP_3:
//                case OP_4:
//                case OP_5:
//                case OP_6:
//                case OP_7:
//                case OP_8:
//                case OP_9:
//                case OP_10:
//                case OP_11:
//                case OP_12:
//                case OP_13:
//                case OP_14:
//                case OP_15:
//                case OP_16:
//                    stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.valueOf(decodeFromOpN(opcode)), false)));
//                    break;
//                case OP_NOP:
//                    break;
//                case OP_VERIFY:
//                    if (stack.size() < 1)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_VERIFY on an empty stack");
//                    if (!castToBool(stack.pollLast()))
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_VERIFY, "OP_VERIFY failed");
//                    break;
//                case OP_RETURN:
//                    throw new ScriptException(ScriptError.SCRIPT_ERR_OP_RETURN, "Script called OP_RETURN");
//                case OP_TOALTSTACK:
//                    if (stack.size() < 1)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_TOALTSTACK on an empty stack");
//                    altstack.add(stack.pollLast());
//                    break;
//                case OP_FROMALTSTACK:
//                    if (altstack.size() < 1)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_ALTSTACK_OPERATION, "Attempted OP_FROMALTSTACK on an empty altstack");
//                    stack.add(altstack.pollLast());
//                    break;
//                case OP_2DROP:
//                    if (stack.size() < 2)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_2DROP on a stack with size < 2");
//                    stack.pollLast();
//                    stack.pollLast();
//                    break;
//                case OP_2DUP:
//                    if (stack.size() < 2)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_2DUP on a stack with size < 2");
//                    Iterator<byte[]> it2DUP = stack.descendingIterator();
//                    byte[] OP2DUPtmpChunk2 = it2DUP.next();
//                    stack.add(it2DUP.next());
//                    stack.add(OP2DUPtmpChunk2);
//                    break;
//                case OP_3DUP:
//                    if (stack.size() < 3)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_3DUP on a stack with size < 3");
//                    Iterator<byte[]> it3DUP = stack.descendingIterator();
//                    byte[] OP3DUPtmpChunk3 = it3DUP.next();
//                    byte[] OP3DUPtmpChunk2 = it3DUP.next();
//                    stack.add(it3DUP.next());
//                    stack.add(OP3DUPtmpChunk2);
//                    stack.add(OP3DUPtmpChunk3);
//                    break;
//                case OP_2OVER:
//                    if (stack.size() < 4)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_2OVER on a stack with size < 4");
//                    Iterator<byte[]> it2OVER = stack.descendingIterator();
//                    it2OVER.next();
//                    it2OVER.next();
//                    byte[] OP2OVERtmpChunk2 = it2OVER.next();
//                    stack.add(it2OVER.next());
//                    stack.add(OP2OVERtmpChunk2);
//                    break;
//                case OP_2ROT:
//                    if (stack.size() < 6)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_2ROT on a stack with size < 6");
//                    byte[] OP2ROTtmpChunk6 = stack.pollLast();
//                    byte[] OP2ROTtmpChunk5 = stack.pollLast();
//                    byte[] OP2ROTtmpChunk4 = stack.pollLast();
//                    byte[] OP2ROTtmpChunk3 = stack.pollLast();
//                    byte[] OP2ROTtmpChunk2 = stack.pollLast();
//                    byte[] OP2ROTtmpChunk1 = stack.pollLast();
//                    stack.add(OP2ROTtmpChunk3);
//                    stack.add(OP2ROTtmpChunk4);
//                    stack.add(OP2ROTtmpChunk5);
//                    stack.add(OP2ROTtmpChunk6);
//                    stack.add(OP2ROTtmpChunk1);
//                    stack.add(OP2ROTtmpChunk2);
//                    break;
//                case OP_2SWAP:
//                    if (stack.size() < 4)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_2SWAP on a stack with size < 4");
//                    byte[] OP2SWAPtmpChunk4 = stack.pollLast();
//                    byte[] OP2SWAPtmpChunk3 = stack.pollLast();
//                    byte[] OP2SWAPtmpChunk2 = stack.pollLast();
//                    byte[] OP2SWAPtmpChunk1 = stack.pollLast();
//                    stack.add(OP2SWAPtmpChunk3);
//                    stack.add(OP2SWAPtmpChunk4);
//                    stack.add(OP2SWAPtmpChunk1);
//                    stack.add(OP2SWAPtmpChunk2);
//                    break;
//                case OP_IFDUP:
//                    if (stack.size() < 1)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_IFDUP on an empty stack");
//                    if (castToBool(stack.getLast()))
//                        stack.add(stack.getLast());
//                    break;
//                case OP_DEPTH:
//                    stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.valueOf(stack.size()), false)));
//                    break;
//                case OP_DROP:
//                    if (stack.size() < 1)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_DROP on an empty stack");
//                    stack.pollLast();
//                    break;
//                case OP_DUP:
//                    if (stack.size() < 1)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_DUP on an empty stack");
//                    stack.add(stack.getLast());
//                    break;
//                case OP_NIP:
//                    if (stack.size() < 2)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_NIP on a stack with size < 2");
//                    byte[] OPNIPtmpChunk = stack.pollLast();
//                    stack.pollLast();
//                    stack.add(OPNIPtmpChunk);
//                    break;
//                case OP_OVER:
//                    if (stack.size() < 2)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_OVER on a stack with size < 2");
//                    Iterator<byte[]> itOVER = stack.descendingIterator();
//                    itOVER.next();
//                    stack.add(itOVER.next());
//                    break;
//                case OP_PICK:
//                case OP_ROLL:
//                    if (stack.size() < 1)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_PICK/OP_ROLL on an empty stack");
//                    long val = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA)).longValue();
//                    if (val < 0 || val >= stack.size())
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "OP_PICK/OP_ROLL attempted to get data deeper than stack size");
//                    Iterator<byte[]> itPICK = stack.descendingIterator();
//                    for (long i = 0; i < val; i++)
//                        itPICK.next();
//                    byte[] OPROLLtmpChunk = itPICK.next();
//                    if (opcode == OP_ROLL)
//                        itPICK.remove();
//                    stack.add(OPROLLtmpChunk);
//                    break;
//                case OP_ROT:
//                    if (stack.size() < 3)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_ROT on a stack with size < 3");
//                    byte[] OPROTtmpChunk3 = stack.pollLast();
//                    byte[] OPROTtmpChunk2 = stack.pollLast();
//                    byte[] OPROTtmpChunk1 = stack.pollLast();
//                    stack.add(OPROTtmpChunk2);
//                    stack.add(OPROTtmpChunk3);
//                    stack.add(OPROTtmpChunk1);
//                    break;
//                case OP_SWAP:
//                case OP_TUCK:
//                    if (stack.size() < 2)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_SWAP on a stack with size < 2");
//                    byte[] OPSWAPtmpChunk2 = stack.pollLast();
//                    byte[] OPSWAPtmpChunk1 = stack.pollLast();
//                    stack.add(OPSWAPtmpChunk2);
//                    stack.add(OPSWAPtmpChunk1);
//                    if (opcode == OP_TUCK)
//                        stack.add(OPSWAPtmpChunk2);
//                    break;
//                case OP_SIZE:
//                    if (stack.size() < 1)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_SIZE on an empty stack");
//                    stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.valueOf(stack.getLast().length), false)));
//                    break;
//                case OP_EQUAL:
//                    if (stack.size() < 2)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_EQUAL on a stack with size < 2");
//                    stack.add(Arrays.equals(stack.pollLast(), stack.pollLast()) ? new byte[] {1} : new byte[] {});
//                    break;
//                case OP_EQUALVERIFY:
//                    if (stack.size() < 2)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_EQUALVERIFY on a stack with size < 2");
//                    if (!Arrays.equals(stack.pollLast(), stack.pollLast()))
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_EQUALVERIFY, "OP_EQUALVERIFY: non-equal data");
//                    break;
//                case OP_1ADD:
//                case OP_1SUB:
//                case OP_NEGATE:
//                case OP_ABS:
//                case OP_NOT:
//                case OP_0NOTEQUAL:
//                    if (stack.size() < 1)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted a numeric op on an empty stack");
//                    BigInteger numericOPnum = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA));
//
//                    switch (opcode) {
//                    case OP_1ADD:
//                        numericOPnum = numericOPnum.add(BigInteger.ONE);
//                        break;
//                    case OP_1SUB:
//                        numericOPnum = numericOPnum.subtract(BigInteger.ONE);
//                        break;
//                    case OP_NEGATE:
//                        numericOPnum = numericOPnum.negate();
//                        break;
//                    case OP_ABS:
//                        if (numericOPnum.signum() < 0)
//                            numericOPnum = numericOPnum.negate();
//                        break;
//                    case OP_NOT:
//                        if (numericOPnum.equals(BigInteger.ZERO))
//                            numericOPnum = BigInteger.ONE;
//                        else
//                            numericOPnum = BigInteger.ZERO;
//                        break;
//                    case OP_0NOTEQUAL:
//                        if (numericOPnum.equals(BigInteger.ZERO))
//                            numericOPnum = BigInteger.ZERO;
//                        else
//                            numericOPnum = BigInteger.ONE;
//                        break;
//                    default:
//                        throw new AssertionError("Unreachable");
//                    }
//
//                    stack.add(Utils.reverseBytes(Utils.encodeMPI(numericOPnum, false)));
//                    break;
//                case OP_ADD:
//                case OP_SUB:
//                case OP_BOOLAND:
//                case OP_BOOLOR:
//                case OP_NUMEQUAL:
//                case OP_NUMNOTEQUAL:
//                case OP_LESSTHAN:
//                case OP_GREATERTHAN:
//                case OP_LESSTHANOREQUAL:
//                case OP_GREATERTHANOREQUAL:
//                case OP_MIN:
//                case OP_MAX:
//                    if (stack.size() < 2)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted a numeric op on a stack with size < 2");
//                    BigInteger numericOPnum2 = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA));
//                    BigInteger numericOPnum1 = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA));
//
//                    BigInteger numericOPresult;
//                    switch (opcode) {
//                    case OP_ADD:
//                        numericOPresult = numericOPnum1.add(numericOPnum2);
//                        break;
//                    case OP_SUB:
//                        numericOPresult = numericOPnum1.subtract(numericOPnum2);
//                        break;
//                    case OP_BOOLAND:
//                        if (!numericOPnum1.equals(BigInteger.ZERO) && !numericOPnum2.equals(BigInteger.ZERO))
//                            numericOPresult = BigInteger.ONE;
//                        else
//                            numericOPresult = BigInteger.ZERO;
//                        break;
//                    case OP_BOOLOR:
//                        if (!numericOPnum1.equals(BigInteger.ZERO) || !numericOPnum2.equals(BigInteger.ZERO))
//                            numericOPresult = BigInteger.ONE;
//                        else
//                            numericOPresult = BigInteger.ZERO;
//                        break;
//                    case OP_NUMEQUAL:
//                        if (numericOPnum1.equals(numericOPnum2))
//                            numericOPresult = BigInteger.ONE;
//                        else
//                            numericOPresult = BigInteger.ZERO;
//                        break;
//                    case OP_NUMNOTEQUAL:
//                        if (!numericOPnum1.equals(numericOPnum2))
//                            numericOPresult = BigInteger.ONE;
//                        else
//                            numericOPresult = BigInteger.ZERO;
//                        break;
//                    case OP_LESSTHAN:
//                        if (numericOPnum1.compareTo(numericOPnum2) < 0)
//                            numericOPresult = BigInteger.ONE;
//                        else
//                            numericOPresult = BigInteger.ZERO;
//                        break;
//                    case OP_GREATERTHAN:
//                        if (numericOPnum1.compareTo(numericOPnum2) > 0)
//                            numericOPresult = BigInteger.ONE;
//                        else
//                            numericOPresult = BigInteger.ZERO;
//                        break;
//                    case OP_LESSTHANOREQUAL:
//                        if (numericOPnum1.compareTo(numericOPnum2) <= 0)
//                            numericOPresult = BigInteger.ONE;
//                        else
//                            numericOPresult = BigInteger.ZERO;
//                        break;
//                    case OP_GREATERTHANOREQUAL:
//                        if (numericOPnum1.compareTo(numericOPnum2) >= 0)
//                            numericOPresult = BigInteger.ONE;
//                        else
//                            numericOPresult = BigInteger.ZERO;
//                        break;
//                    case OP_MIN:
//                        if (numericOPnum1.compareTo(numericOPnum2) < 0)
//                            numericOPresult = numericOPnum1;
//                        else
//                            numericOPresult = numericOPnum2;
//                        break;
//                    case OP_MAX:
//                        if (numericOPnum1.compareTo(numericOPnum2) > 0)
//                            numericOPresult = numericOPnum1;
//                        else
//                            numericOPresult = numericOPnum2;
//                        break;
//                    default:
//                        throw new RuntimeException("Opcode switched at runtime?");
//                    }
//
//                    stack.add(Utils.reverseBytes(Utils.encodeMPI(numericOPresult, false)));
//                    break;
//                case OP_NUMEQUALVERIFY:
//                    if (stack.size() < 2)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_NUMEQUALVERIFY on a stack with size < 2");
//                    BigInteger OPNUMEQUALVERIFYnum2 = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA));
//                    BigInteger OPNUMEQUALVERIFYnum1 = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA));
//
//                    if (!OPNUMEQUALVERIFYnum1.equals(OPNUMEQUALVERIFYnum2))
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_NUMEQUALVERIFY, "OP_NUMEQUALVERIFY failed");
//                    break;
//                case OP_WITHIN:
//                    if (stack.size() < 3)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_WITHIN on a stack with size < 3");
//                    BigInteger OPWITHINnum3 = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA));
//                    BigInteger OPWITHINnum2 = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA));
//                    BigInteger OPWITHINnum1 = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA));
//                    if (OPWITHINnum2.compareTo(OPWITHINnum1) <= 0 && OPWITHINnum1.compareTo(OPWITHINnum3) < 0)
//                        stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.ONE, false)));
//                    else
//                        stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.ZERO, false)));
//                    break;
//                case OP_RIPEMD160:
//                    if (stack.size() < 1)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_RIPEMD160 on an empty stack");
//                    RIPEMD160Digest digest = new RIPEMD160Digest();
//                    byte[] dataToHash = stack.pollLast();
//                    digest.update(dataToHash, 0, dataToHash.length);
//                    byte[] ripmemdHash = new byte[20];
//                    digest.doFinal(ripmemdHash, 0);
//                    stack.add(ripmemdHash);
//                    break;
//                case OP_SHA1:
//                    if (stack.size() < 1)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_SHA1 on an empty stack");
//                    try {
//                        stack.add(MessageDigest.getInstance("SHA-1").digest(stack.pollLast()));
//                    } catch (NoSuchAlgorithmException e) {
//                        throw new RuntimeException(e);  // Cannot happen.
//                    }
//                    break;
//                case OP_SHA256:
//                    if (stack.size() < 1)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_SHA256 on an empty stack");
//                    stack.add(Sha256Hash.hash(stack.pollLast()));
//                    break;
//                case OP_HASH160:
//                    if (stack.size() < 1)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_HASH160 on an empty stack");
//                    stack.add(Utils.sha256hash160(stack.pollLast()));
//                    break;
//                case OP_HASH256:
//                    if (stack.size() < 1)
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_SHA256 on an empty stack");
//                    stack.add(Sha256Hash.hashTwice(stack.pollLast()));
//                    break;
//                case OP_CODESEPARATOR:
//                    lastCodeSepLocation = nextLocationInScript;
//                    break;
//                case OP_CHECKSIG:
//                case OP_CHECKSIGVERIFY:
//                    if (txContainingThis == null)
//                        throw new IllegalStateException("Script attempted signature check but no tx was provided");
//                    executeCheckSig(txContainingThis, (int) index, script, stack, lastCodeSepLocation, opcode, verifyFlags);
//                    break;
//                case OP_CHECKMULTISIG:
//                case OP_CHECKMULTISIGVERIFY:
//                    if (txContainingThis == null)
//                        throw new IllegalStateException("Script attempted signature check but no tx was provided");
//                    opCount = executeMultiSig(txContainingThis, (int) index, script, stack, opCount, lastCodeSepLocation, opcode, verifyFlags);
//                    break;
//                case OP_CHECKLOCKTIMEVERIFY:
//                    if (!verifyFlags.contains(VerifyFlag.CHECKLOCKTIMEVERIFY)) {
//                        // not enabled; treat as a NOP2
//                        if (verifyFlags.contains(VerifyFlag.DISCOURAGE_UPGRADABLE_NOPS)) {
//                            throw new ScriptException(ScriptError.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS, "Script used a reserved opcode " + opcode);
//                        }
//                        break;
//                    }
//                    executeCheckLockTimeVerify(txContainingThis, (int) index, stack, verifyFlags);
//                    break;
//                case OP_CHECKSEQUENCEVERIFY:
//                    if (!verifyFlags.contains(VerifyFlag.CHECKSEQUENCEVERIFY)) {
//                        // not enabled; treat as a NOP3
//                        if (verifyFlags.contains(VerifyFlag.DISCOURAGE_UPGRADABLE_NOPS)) {
//                            throw new ScriptException(ScriptError.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS, "Script used a reserved opcode " + opcode);
//                        }
//                        break;
//                    }
//                    executeCheckSequenceVerify(txContainingThis, (int) index, stack, verifyFlags);
//                    break;
//                case OP_NOP1:
//                case OP_NOP4:
//                case OP_NOP5:
//                case OP_NOP6:
//                case OP_NOP7:
//                case OP_NOP8:
//                case OP_NOP9:
//                case OP_NOP10:
//                    if (verifyFlags.contains(VerifyFlag.DISCOURAGE_UPGRADABLE_NOPS)) {
//                        throw new ScriptException(ScriptError.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS, "Script used a reserved opcode " + opcode);
//                    }
//                    break;
//
//                default:
//                    throw new ScriptException(ScriptError.SCRIPT_ERR_BAD_OPCODE, "Script used a reserved or disabled opcode: " + opcode);
//                }
//            }
//
//            if (stack.size() + altstack.size() > MAX_STACK_SIZE || stack.size() + altstack.size() < 0)
//                throw new ScriptException(ScriptError.SCRIPT_ERR_STACK_SIZE, "Stack size exceeded range");
//        }
//
//        if (!ifStack.isEmpty())
//            throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "OP_IF/OP_NOTIF without OP_ENDIF");
//    }
//


    // Utility that doesn't copy for internal use
    private byte[] getQuickProgram() {
        if (program != null)
            return program;
        return getProgram();
    }

    /**
     * Get the {@link ScriptType}.
     * @return The script type, or null if the script is of unknown type
     */
    public @Nullable ScriptType getScriptType() {
        if (ScriptPattern.isP2PKH(this))
            return ScriptType.P2PKH;
        if (ScriptPattern.isP2PK(this))
            return ScriptType.P2PK;
        if (ScriptPattern.isP2SH(this))
            return ScriptType.P2SH;
        return null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return Arrays.equals(getQuickProgram(), ((Script)o).getQuickProgram());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(getQuickProgram());
    }
}
