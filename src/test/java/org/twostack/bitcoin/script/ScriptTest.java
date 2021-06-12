/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
 * Copyright 2017 Thomas König
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

//import org.twostack.bitcoin.transaction.Transaction.SigHash;
//import org.twostack.bitcoin.crypto.TransactionSignature;
//import org.twostack.bitcoin.params.MainNetParams;
//import org.twostack.bitcoin.params.TestNet3Params;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.twostack.bitcoin.Sha256Hash;
import org.twostack.bitcoin.UnsafeByteArrayOutputStream;
import org.twostack.bitcoin.Utils;
        import org.twostack.bitcoin.script.Script.VerifyFlag;
        import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.twostack.bitcoin.transaction.Transaction;
import org.twostack.bitcoin.transaction.TransactionInput;
import org.twostack.bitcoin.transaction.TransactionOutput;

import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.twostack.bitcoin.Utils.HEX;
        import static org.twostack.bitcoin.script.ScriptOpCodes.OP_INVALIDOPCODE;
        import static org.junit.Assert.*;

public class ScriptTest {
    // From tx 05e04c26c12fe408a3c1b71aa7996403f6acad1045252b1c62e055496f4d2cb1 on the testnet.

    private static final String sigProg = "47304402202b4da291cc39faf8433911988f9f49fc5c995812ca2f94db61468839c228c3e90220628bff3ff32ec95825092fa051cba28558a981fcf59ce184b14f2e215e69106701410414b38f4be3bb9fa0f4f32b74af07152b2f2f630bc02122a491137b6c523e46f18a0d5034418966f93dfc37cc3739ef7b2007213a302b7fba161557f4ad644a1c";

    private static final String pubkeyProg = "76a91433e81a941e64cda12c6a299ed322ddbdd03f8d0e88ac";

    private static final Logger log = LoggerFactory.getLogger(ScriptTest.class);

    @Before
    public void setUp() throws Exception {
    }

    @Test
    public void testScriptSig() throws Exception {
        byte[] sigProgBytes = HEX.decode(sigProg);
        Script script = new Script(sigProgBytes);
        assertEquals(
                "PUSHDATA(71)[304402202b4da291cc39faf8433911988f9f49fc5c995812ca2f94db61468839c228c3e90220628bff3ff32ec95825092fa051cba28558a981fcf59ce184b14f2e215e69106701] PUSHDATA(65)[0414b38f4be3bb9fa0f4f32b74af07152b2f2f630bc02122a491137b6c523e46f18a0d5034418966f93dfc37cc3739ef7b2007213a302b7fba161557f4ad644a1c]",
                script.toString());
    }


    @Test
    public void parse_buffer_containing_OP_0() {
        byte[] programBytes = {ScriptOpCodes.OP_0};
        Script script = Script.fromByteArray(programBytes);

        assertArrayEquals(programBytes, script.getProgram());
    }


    @Test
    public void parse_buffer_containing_OP_CHECKMULTISIG() {
        ScriptBuilder builder = new ScriptBuilder();
        builder.op(ScriptOpCodes.OP_CHECKMULTISIG);
        Script program = builder.build();

        assertEquals(HEX.encode(program.getProgram()), "ae");
    }


    @Test
    public void should_parse_these_three_data_bytes() {
        ScriptBuilder builder = new ScriptBuilder();
        builder.data(new byte[]{1,2,3});
        Script program = builder.build();

        assertEquals(HEX.encode(program.getProgram()), "03010203");
    }

    @Test
    public void should_parse_these_known_scripts(){

        String parsed = Script.fromAsmString("0 PUSHDATA4 3 0x010203 0").toAsmString();
        assertEquals("0 PUSHDATA4 3 0x010203 0", parsed);

        String parsed2 = Script.fromAsmString("0 PUSHDATA2 3 0x010203 0").toAsmString();
        assertEquals("0 PUSHDATA2 3 0x010203 0", parsed2);

        String parsed3 = Script.fromAsmString("0 PUSHDATA1 3 0x010203 0").toAsmString();
        assertEquals("0 PUSHDATA1 3 0x010203 0", parsed3);

        String parsed4 = Script.fromAsmString("0 3 0x010203 0").toAsmString();
        assertEquals("0 3 0x010203 0", parsed4);
    }


    @Test
    public void can_roundtrip_serializing_of_a_script(){

        final String str = "0 RETURN 34 0x31346b7871597633656d48477766386d36596753594c516b4743766e395172677239 66 0x303236336661663734633031356630376532633834343538623566333035653262323762366566303838393238383133326435343264633139633436663064663532 PUSHDATA1 150 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        final Script script = Script.fromAsmString(str);

        assertEquals(str, script.toAsmString());
    }

    /// fromByteArray constructor tests
    @Test
    public void should_parse_buffer_with_op_code(){
        byte[] buf = new byte[1];
        buf[0] = ScriptOpCodes.OP_0;
        Script script = Script.fromByteArray(buf);
        assertEquals(script.chunks.size(), 1);
        assertEquals(script.chunks.get(0).opcode, buf[0]);

    }

    @Test
    public void should_parse_buffer_with_data(){
        byte[] buf = new byte[]{3,1,2,3};
        Script script = Script.fromByteArray(buf);
        assertEquals(HEX.encode(script.chunks.get(0).data), "010203");
    }

    @Test
    public void should_parse_this_asm_script(){
        String asm = "DUP HASH160 20 0xf4c03610e60ad15100929cc23da2f3a799af1725 EQUALVERIFY CHECKSIG";
        Script script = Script.fromAsmString(asm);

        assertEquals(script.chunks.get(0).opcode, ScriptOpCodes.OP_DUP);
        assertEquals(script.chunks.get(1).opcode, ScriptOpCodes.OP_HASH160);
        assertEquals(script.chunks.get(2).opcode, 20);
        assertEquals(HEX.encode(script.chunks.get(2).data), "f4c03610e60ad15100929cc23da2f3a799af1725");
        assertEquals(script.chunks.get(3).opcode, ScriptOpCodes.OP_EQUALVERIFY);
        assertEquals(script.chunks.get(4).opcode, ScriptOpCodes.OP_CHECKSIG);
    }


    @Test
    public void should_parse_this_second_asm_script(){
        String asm = "RETURN 3 0x026d02 6 0x0568656c6c6f";
        Script script = Script.fromAsmString(asm);

        assertEquals(script.toAsmString(), asm);
    }

    @Test
    public void should_fail_on_invalid_hex(){
        String asm = "RETURN 3 0x026d02 7 0x0568656c6c6fzz";

        assertThrows(ScriptException.class, () -> Script.fromAsmString(asm));
    }


    private Set<VerifyFlag> parseVerifyFlags(String str) {
        Set<VerifyFlag> flags = EnumSet.noneOf(VerifyFlag.class);
        if (!"NONE".equals(str)) {
            for (String flag : str.split(",")) {
                try {
                    flags.add(VerifyFlag.valueOf(flag));
                } catch (IllegalArgumentException x) {
                    log.debug("Cannot handle verify flag {} -- ignored.", flag);
                }
            }
        }
        return flags;
    }

//   FIXME: What is this meant to be used for ???
//    private Map<TransactionOutput, Script> parseScriptPubKeys(JsonNode inputs) throws IOException {
//        Map<TransactionOutput, Script> scriptPubKeys = new HashMap<>();
//        for (JsonNode input : inputs) {
//            String hash = input.get(0).asText();
//            int index = input.get(1).asInt();
//            String script = input.get(2).asText();
//            Sha256Hash sha256Hash = Sha256Hash.wrap(HEX.decode(hash));
//            scriptPubKeys.put(new TransactionOutput(TESTNET, index, sha256Hash), parseScriptString(script));
//        }
//        return scriptPubKeys;
//    }
//

    private Script parseScriptString(String string) throws IOException {
        String[] words = string.split("[ \\t\\n]");

        UnsafeByteArrayOutputStream out = new UnsafeByteArrayOutputStream();

        for(String w : words) {
            if (w.equals(""))
                continue;
            if (w.matches("^-?[0-9]*$")) {
                // Number
                long val = Long.parseLong(w);
                if (val >= -1 && val <= 16)
                    out.write(Script.encodeToOpN((int)val));
                else
                    Script.writeBytes(out, Utils.reverseBytes(Utils.encodeMPI(BigInteger.valueOf(val), false)));
            } else if (w.matches("^0x[0-9a-fA-F]*$")) {
                // Raw hex data, inserted NOT pushed onto stack:
                out.write(HEX.decode(w.substring(2).toLowerCase()));
            } else if (w.length() >= 2 && w.startsWith("'") && w.endsWith("'")) {
                // Single-quoted string, pushed as data. NOTE: this is poor-man's
                // parsing, spaces/tabs/newlines in single-quoted strings won't work.
                Script.writeBytes(out, w.substring(1, w.length() - 1).getBytes(StandardCharsets.UTF_8));
            } else if (ScriptOpCodes.getOpCode(w) != OP_INVALIDOPCODE) {
                // opcode, e.g. OP_ADD or OP_1:
                out.write(ScriptOpCodes.getOpCode(w));
            } else if (w.startsWith("OP_") && ScriptOpCodes.getOpCode(w.substring(3)) != OP_INVALIDOPCODE) {
                // opcode, e.g. OP_ADD or OP_1:
                out.write(ScriptOpCodes.getOpCode(w.substring(3)));
            } else {
                throw new RuntimeException("Invalid word: '" + w + "'");
            }
        }

        return new Script(out.toByteArray());
    }



//    test("bitcoind invalid transaction evaluation fixtures", () async {
//        await File("${Directory.current.path}/test/data/bitcoind/tx_invalid.json")
//                .readAsString()
//                .then((contents) => jsonDecode(contents))
//            .then((jsonData) {
//                List.from(jsonData).forEach((vect) {
//                        testTransaction(vect, false);
//            });
//        });
//    });


//  FIXME: These test vectors are important
//    @Test
//    public void dataDrivenScripts() throws Exception {
//        JsonNode json = new ObjectMapper()
//                .readTree(new InputStreamReader(getClass().getResourceAsStream("script_tests.json"), StandardCharsets.UTF_8));
//        for (JsonNode test : json) {
//            if (test.size() == 1)
//                continue; // skip comment
//            Set<VerifyFlag> verifyFlags = parseVerifyFlags(test.get(2).asText());
//            ScriptError expectedError = ScriptError.fromMnemonic(test.get(3).asText());
//            try {
//                Script scriptSig = parseScriptString(test.get(0).asText());
//                Script scriptPubKey = parseScriptString(test.get(1).asText());
//                Transaction txCredit = buildCreditingTransaction(scriptPubKey);
//                Transaction txSpend = buildSpendingTransaction(txCredit, scriptSig);
//                scriptSig.correctlySpends(txSpend, 0, null, null, scriptPubKey, verifyFlags);
//                if (!expectedError.equals(ScriptError.SCRIPT_ERR_OK))
//                    fail(test + " is expected to fail");
//            } catch (ScriptException e) {
//                if (!e.getError().equals(expectedError)) {
//                    System.err.println(test);
//                    e.printStackTrace();
//                    System.err.flush();
//                    throw e;
//                }
//            }
//        }
//    }

//    private Map<TransactionOutPoint, Script> parseScriptPubKeys(JsonNode inputs) throws IOException {
//        Map<TransactionOutPoint, Script> scriptPubKeys = new HashMap<>();
//        for (JsonNode input : inputs) {
//            String hash = input.get(0).asText();
//            int index = input.get(1).asInt();
//            String script = input.get(2).asText();
//            Sha256Hash sha256Hash = Sha256Hash.wrap(HEX.decode(hash));
//            scriptPubKeys.put(new TransactionOutPoint(TESTNET, index, sha256Hash), parseScriptString(script));
//        }
//        return scriptPubKeys;
//    }

//    private Transaction buildCreditingTransaction(Script scriptPubKey) {
//        Transaction tx = new Transaction(TESTNET);
//        tx.setVersion(1);
//        tx.setLockTime(0);
//
//        TransactionInput txInput = new TransactionInput(TESTNET, null,
//                new ScriptBuilder().number(0).number(0).build().getProgram());
//        txInput.setSequenceNumber(TransactionInput.NO_SEQUENCE);
//        tx.addInput(txInput);
//
//        TransactionOutput txOutput = new TransactionOutput(TESTNET, tx, Coin.ZERO, scriptPubKey.getProgram());
//        tx.addOutput(txOutput);
//
//        return tx;
//    }

//    private Transaction buildSpendingTransaction(Transaction creditingTransaction, Script scriptSig) {
//        Transaction tx = new Transaction(TESTNET);
//        tx.setVersion(1);
//        tx.setLockTime(0);
//
//        TransactionInput txInput = new TransactionInput(TESTNET, creditingTransaction, scriptSig.getProgram());
//        txInput.setSequenceNumber(TransactionInput.NO_SEQUENCE);
//        tx.addInput(txInput);
//
//        TransactionOutput txOutput = new TransactionOutput(TESTNET, tx, creditingTransaction.getOutput(0).getValue(),
//                new Script(new byte[] {}).getProgram());
//        tx.addOutput(txOutput);
//
//        return tx;
//    }


// FIXME: These vectors are important
//    @Test
//    public void dataDrivenValidTransactions() throws Exception {
//        JsonNode json = new ObjectMapper().readTree(new InputStreamReader(getClass().getResourceAsStream(
//                "tx_valid.json"), StandardCharsets.UTF_8));
//        for (JsonNode test : json) {
//            if (test.isArray() && test.size() == 1 && test.get(0).isTextual())
//                continue; // This is a comment.
//            Transaction transaction = null;
//            try {
//                Map<TransactionOutPoint, Script> scriptPubKeys = parseScriptPubKeys(test.get(0));
//                transaction = TESTNET.getDefaultSerializer().makeTransaction(HEX.decode(test.get(1).asText().toLowerCase()));
//                transaction.verify();
//                Set<VerifyFlag> verifyFlags = parseVerifyFlags(test.get(2).asText());
//
//                for (int i = 0; i < transaction.getInputs().size(); i++) {
//                    TransactionInput input = transaction.getInputs().get(i);
//                    if (input.getOutpoint().getIndex() == 0xffffffffL)
//                        input.getOutpoint().setIndex(-1);
//                    assertTrue(scriptPubKeys.containsKey(input.getOutpoint()));
//                    input.getScriptSig().correctlySpends(transaction, i, null, null,
//                            scriptPubKeys.get(input.getOutpoint()), verifyFlags);
//                }
//            } catch (Exception e) {
//                System.err.println(test);
//                if (transaction != null)
//                    System.err.println(transaction);
//                throw e;
//            }
//        }
//    }



// FIXME: These vectors are important
//    @Test
//    public void dataDrivenInvalidTransactions() throws Exception {
//        JsonNode json = new ObjectMapper().readTree(new InputStreamReader(getClass().getResourceAsStream(
//                "tx_invalid.json"), StandardCharsets.UTF_8));
//        for (JsonNode test : json) {
//            if (test.isArray() && test.size() == 1 && test.get(0).isTextual())
//                continue; // This is a comment.
//            Map<TransactionOutPoint, Script> scriptPubKeys = parseScriptPubKeys(test.get(0));
//            byte[] txBytes = HEX.decode(test.get(1).asText().toLowerCase());
//            MessageSerializer serializer = TESTNET.getDefaultSerializer();
//            Transaction transaction;
//            try {
//                transaction = serializer.makeTransaction(txBytes);
//            } catch (ProtocolException ignore) {
//                // Try to parse as a no-witness transaction because some vectors are 0-input, 1-output txs that fail
//                // to correctly parse as witness transactions.
//                int protoVersionNoWitness = serializer.getProtocolVersion() | SERIALIZE_TRANSACTION_NO_WITNESS;
//                transaction = serializer.withProtocolVersion(protoVersionNoWitness).makeTransaction(txBytes);
//            }
//            Set<VerifyFlag> verifyFlags = parseVerifyFlags(test.get(2).asText());
//
//            boolean valid = true;
//            try {
//                transaction.verify();
//            } catch (VerificationException e) {
//                valid = false;
//            }
//
//            // Bitcoin Core checks this case in CheckTransaction, but we leave it to
//            // later where we will see an attempt to double-spend, so we explicitly check here
//            HashSet<TransactionOutPoint> set = new HashSet<>();
//            for (TransactionInput input : transaction.getInputs()) {
//                if (set.contains(input.getOutpoint()))
//                    valid = false;
//                set.add(input.getOutpoint());
//            }
//
//            for (int i = 0; i < transaction.getInputs().size() && valid; i++) {
//                TransactionInput input = transaction.getInputs().get(i);
//                assertTrue(scriptPubKeys.containsKey(input.getOutpoint()));
//                try {
//                    input.getScriptSig().correctlySpends(transaction, i, null, null,
//                            scriptPubKeys.get(input.getOutpoint()), verifyFlags);
//                } catch (VerificationException e) {
//                    valid = false;
//                }
//            }
//
//            if (valid) {
//                System.out.println(test);
//                fail();
//            }
//        }
//    }


//    @Test(expected = ScriptException.class)
//    public void getToAddressNoPubKey() throws Exception {
//        ScriptBuilder.createP2PKOutputScript(new ECKey()).getToAddress(TESTNET, false);
//    }
}
