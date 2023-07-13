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

package org.twostack.bitcoin4j.script;

import at.favre.lib.bytes.Bytes;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Charsets;
import org.twostack.bitcoin4j.Coin;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.exception.TransactionException;
import org.twostack.bitcoin4j.exception.VerificationException;
import org.twostack.bitcoin4j.script.Script.VerifyFlag;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.twostack.bitcoin4j.transaction.*;

import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.twostack.bitcoin4j.Utils.HEX;
import static org.junit.Assert.*;
import static org.twostack.bitcoin4j.utils.TestUtil.parseScriptString;
import static org.twostack.bitcoin4j.utils.TestUtil.parseVerifyFlags;

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
    public void should_parse_these_known_scripts() throws IOException {

        String parsed = Script.fromBitcoindString("OP_0 OP_PUSHDATA4 3 0x010203 OP_0").toBitcoindString();
        assertEquals("OP_0 OP_PUSHDATA4 3 0x010203 OP_0", parsed);

        String parsed2 = Script.fromBitcoindString("OP_0 OP_PUSHDATA2 3 0x010203 OP_0").toBitcoindString();
        assertEquals("OP_0 OP_PUSHDATA2 3 0x010203 OP_0", parsed2);

        String parsed3 = Script.fromBitcoindString("OP_0 OP_PUSHDATA1 3 0x010203 OP_0").toBitcoindString();
        assertEquals("OP_0 OP_PUSHDATA1 3 0x010203 OP_0", parsed3);

        String parsed4 = Script.fromBitcoindString("OP_0 3 0x010203 OP_0").toBitcoindString();
        assertEquals("OP_0 3 0x010203 OP_0", parsed4);
    }


    @Test
    public void can_roundtrip_serializing_of_a_script() throws IOException {

        final String str = "OP_0 OP_RETURN 34 0x31346b7871597633656d48477766386d36596753594c516b4743766e395172677239 66 0x303236336661663734633031356630376532633834343538623566333035653262323762366566303838393238383133326435343264633139633436663064663532 OP_PUSHDATA1 150 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        final Script script = Script.fromBitcoindString(str);

        assertEquals(str, script.toBitcoindString());
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
    public void should_parse_this_asm_script() throws IOException {
        String asm = "OP_DUP OP_HASH160 20 0xf4c03610e60ad15100929cc23da2f3a799af1725 OP_EQUALVERIFY OP_CHECKSIG";
        Script script = Script.fromBitcoindString(asm);

        assertEquals(script.chunks.get(0).opcode, ScriptOpCodes.OP_DUP);
        assertEquals(script.chunks.get(1).opcode, ScriptOpCodes.OP_HASH160);
        assertEquals(script.chunks.get(2).opcode, 20);
        assertEquals(HEX.encode(script.chunks.get(2).data), "f4c03610e60ad15100929cc23da2f3a799af1725");
        assertEquals(script.chunks.get(3).opcode, ScriptOpCodes.OP_EQUALVERIFY);
        assertEquals(script.chunks.get(4).opcode, ScriptOpCodes.OP_CHECKSIG);
    }


    @Test
    public void should_parse_this_second_asm_script() throws IOException {
        String asm = "OP_RETURN 3 0x026d02 6 0x0568656c6c6f";
        Script script = Script.fromBitcoindString(asm);

        assertEquals(script.toBitcoindString(), asm);
    }

    @Test
    public void should_fail_on_invalid_hex(){
        String asm = "OP_RETURN 3 0x026d02 7 0x0568656c6c6fzz";

        assertThrows(ScriptException.class, () -> Script.fromBitcoindString(asm));
    }

    private Transaction buildCreditingTransaction(Script scriptPubKey, BigInteger nValue) throws TransactionException {

        Transaction credTx = new Transaction();
        Script unlockingScript = new ScriptBuilder().number(0).number(0).build();
        DefaultUnlockBuilder coinbaseUnlockBuilder = new DefaultUnlockBuilder(unlockingScript);
        byte[] prevTxnId = new byte[32];
        TransactionInput coinbaseInput = new TransactionInput(
                prevTxnId,
                0xffffffff,
                TransactionInput.MAX_SEQ_NUMBER,
                coinbaseUnlockBuilder
        );
        credTx.addInput(coinbaseInput);

        LockingScriptBuilder lockingScriptBuilder = new DefaultLockBuilder(scriptPubKey);
        TransactionOutput output = new TransactionOutput(nValue, lockingScriptBuilder);

        credTx.addOutput(output);

        return credTx;


    }

    private Transaction buildSpendingTransaction(Transaction creditingTransaction, Script scriptSig) {

        Transaction spendingTx = new Transaction();

        UnlockingScriptBuilder unlockingScriptBuilder = new DefaultUnlockBuilder(scriptSig);

        TransactionInput input = new TransactionInput(
                Utils.reverseBytes(creditingTransaction.getTransactionIdBytes()),
                0,
                TransactionInput.MAX_SEQ_NUMBER,
                unlockingScriptBuilder
        );
        spendingTx.addInput(input);

        LockingScriptBuilder lockingScriptBuilder = new DefaultLockBuilder(new ScriptBuilder().build());
        TransactionOutput output = new TransactionOutput(BigInteger.ZERO, lockingScriptBuilder);
        spendingTx.addOutput(output);

        return spendingTx;

    }
    @Test
    public void dataDrivenScripts() throws Exception {
        JsonNode json = new ObjectMapper()
                .readTree(new InputStreamReader(getClass().getResourceAsStream("script_tests_svnode.json"), StandardCharsets.UTF_8));
        for (JsonNode test : json) {
            if (test.size() == 1)
                continue; // skip comment

            String nValue = "0";
            int offset = 0;
            if (test.size() == 6 && test.get(0).isArray()){
                //grab the satoshi value from first array
                nValue = test.get(0).get(0).asText();
                offset = 1;
            }

            Set<VerifyFlag> verifyFlags = parseVerifyFlags(test.get(offset + 2).asText());
            ScriptError expectedError = ScriptError.fromMnemonic(test.get(offset + 3).asText());
            System.out.println(test.get(offset + 1).asText());
            try {
                Script scriptSig = parseScriptString(test.get(offset + 0).asText());
                Script scriptPubKey = parseScriptString(test.get(offset + 1).asText());
                Transaction txCredit = buildCreditingTransaction(scriptPubKey,BigInteger.ZERO).setVersion(1);
                Transaction txSpend = buildSpendingTransaction(txCredit, scriptSig).setVersion(1);

                Interpreter interp = new Interpreter();
                interp.correctlySpends(scriptSig, scriptPubKey, txSpend, 0,  verifyFlags);
                if (!expectedError.equals(ScriptError.SCRIPT_ERR_OK))
                    fail(test + " is expected to fail");
            } catch (ScriptException e) {
                if (!e.getError().equals(expectedError)) {
                    System.err.println(test);
                    e.printStackTrace();
                    System.err.flush();
                    throw e;
                }
            }
        }
    }





    @Test
    public void parseKnownAsm() throws IOException {
        String asm = "OP_DUP OP_HASH160 f4c03610e60ad15100929cc23da2f3a799af1725 OP_EQUALVERIFY OP_CHECKSIG";
        Script script = Script.fromAsmString(asm);
        assertEquals(ScriptOpCodes.OP_DUP, script.getChunks().get(0).opcode);
        assertEquals(ScriptOpCodes.OP_HASH160, script.getChunks().get(1).opcode);
        assertEquals(20, script.getChunks().get(2).opcode);
        assertEquals( "f4c03610e60ad15100929cc23da2f3a799af1725", HEX.encode(script.getChunks().get(2).data));
        assertEquals( ScriptOpCodes.OP_EQUALVERIFY, script.getChunks().get(3).opcode);
        assertEquals( ScriptOpCodes.OP_CHECKSIG, script.getChunks().get(4).opcode);

    }

    @Test
    public void convertKnownAsm() throws IOException{
        Script script = Script.fromAsmString("OP_DUP OP_HASH160 6fa5502ea094d59576898b490d866b32a61b89f6 OP_EQUALVERIFY OP_CHECKSIG");

        assertEquals("OP_DUP OP_HASH160 6fa5502ea094d59576898b490d866b32a61b89f6 OP_EQUALVERIFY OP_CHECKSIG", script.toAsmString());
    }


    @Test
    public void shouldHandleAsmFalse() {
        String asm1 = "OP_FALSE";
        String asm2 = "OP_0";
        String asm3 = "0";
        assertEquals(Script.fromAsmString(asm1).toAsmString(), asm3);
        assertEquals(Script.fromAsmString(asm2).toAsmString(), asm3);
        assertEquals(Script.fromAsmString(asm3).toAsmString(), asm3);
    }

    @Test
    public void shouldHandleAsmNegate() {
        String asm1 = "OP_1NEGATE";
        String asm2 = "-1";
        assertEquals(Script.fromAsmString(asm1).toAsmString(),asm2);
        assertEquals(Script.fromAsmString(asm2).toAsmString(),asm2);
    }

    @Test
    public void parseKnownProblematic() {
        String asm = "OP_RETURN 3 0x026d02 6 0x0568656c6c6f";
        Script script = Script.fromBitcoindString(asm);
        assertEquals(asm, script.toBitcoindString());
    }

    @Test
    public void failsOnInvalidHex(){
        String asm = "OP_RETURN 026d02 0568656c6c6fzz";
        assertThrows(ScriptException.class, () -> Script.fromBitcoindString(asm));
    }

    @Test
    public void shouldParseLongPushData(){

        byte[] buf = new byte[220];
        String asm = "OP_0 OP_RETURN OP_PUSHDATA1 220 0x" + HEX.encode(buf);
        Script script = Script.fromBitcoindString(asm);
        assertEquals(ScriptOpCodes.OP_PUSHDATA1, script.getChunks().get(2).opcode);
        assertEquals(asm, script.toBitcoindString());
    }

    @Test
    public void shouldParseLongPushData2(){
        byte[] buf = new byte[1024];
        String asm = "OP_0 OP_RETURN OP_PUSHDATA2 1024 0x" + HEX.encode(buf);
        Script script = Script.fromBitcoindString(asm);
        assertEquals(ScriptOpCodes.OP_PUSHDATA2, script.getChunks().get(2).opcode);
        assertEquals(asm, script.toBitcoindString());
    }

    @Test
    public void shouldParseLongPushData4(){
        int doubleSize = Double.valueOf(Math.pow(2, 17)).intValue();
        byte[] buf = new byte[doubleSize];
        String asm = "OP_0 OP_RETURN OP_PUSHDATA4 " + doubleSize + " 0x" + HEX.encode(buf);
        Script script = Script.fromBitcoindString(asm);
        assertEquals(ScriptOpCodes.OP_PUSHDATA4, script.getChunks().get(2).opcode);
        assertEquals(asm, script.toBitcoindString());
    }

    @Test
    public void shouldRenderP2PKH() {
        Script script = new Script(HEX.decode("76a914f4c03610e60ad15100929cc23da2f3a799af172588ac"));
        assertEquals("OP_DUP OP_HASH160 20 0xf4c03610e60ad15100929cc23da2f3a799af1725 OP_EQUALVERIFY OP_CHECKSIG",  script.toBitcoindString());
    }


}
