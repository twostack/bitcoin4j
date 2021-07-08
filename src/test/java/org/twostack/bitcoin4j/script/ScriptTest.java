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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Charsets;
import org.twostack.bitcoin4j.exception.VerificationException;
import org.twostack.bitcoin4j.script.Script.VerifyFlag;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.twostack.bitcoin4j.transaction.Transaction;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.*;

import static org.twostack.bitcoin4j.Utils.HEX;
import static org.junit.Assert.*;
import static org.twostack.bitcoin4j.utils.TestUtil.parseScriptString;

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

        String parsed = Script.fromAsmString("OP_0 OP_PUSHDATA4 3 0x010203 OP_0").toAsmString();
        assertEquals("OP_0 OP_PUSHDATA4 3 0x010203 OP_0", parsed);

        String parsed2 = Script.fromAsmString("OP_0 OP_PUSHDATA2 3 0x010203 OP_0").toAsmString();
        assertEquals("OP_0 OP_PUSHDATA2 3 0x010203 OP_0", parsed2);

        String parsed3 = Script.fromAsmString("OP_0 OP_PUSHDATA1 3 0x010203 OP_0").toAsmString();
        assertEquals("OP_0 OP_PUSHDATA1 3 0x010203 OP_0", parsed3);

        String parsed4 = Script.fromAsmString("OP_0 3 0x010203 OP_0").toAsmString();
        assertEquals("OP_0 3 0x010203 OP_0", parsed4);
    }


    @Test
    public void can_roundtrip_serializing_of_a_script() throws IOException {

        final String str = "OP_0 OP_RETURN 34 0x31346b7871597633656d48477766386d36596753594c516b4743766e395172677239 66 0x303236336661663734633031356630376532633834343538623566333035653262323762366566303838393238383133326435343264633139633436663064663532 OP_PUSHDATA1 150 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
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
    public void should_parse_this_asm_script() throws IOException {
        String asm = "OP_DUP OP_HASH160 20 0xf4c03610e60ad15100929cc23da2f3a799af1725 OP_EQUALVERIFY OP_CHECKSIG";
        Script script = Script.fromAsmString(asm);

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
        Script script = Script.fromAsmString(asm);

        assertEquals(script.toAsmString(), asm);
    }

    @Test
    public void should_fail_on_invalid_hex(){
        String asm = "OP_RETURN 3 0x026d02 7 0x0568656c6c6fzz";

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




    @Test
    public void dataDrivenValidScripts() throws Exception {
        JsonNode json = new ObjectMapper().readTree(new InputStreamReader(getClass().getResourceAsStream(
                "script_valid.json"), Charsets.UTF_8));
        for (JsonNode test : json) {
            Script scriptSig = parseScriptString(test.get(0).asText());
            Script scriptPubKey = parseScriptString(test.get(1).asText());
            Set<VerifyFlag> verifyFlags = parseVerifyFlags(test.get(2).asText());
            try {


                Interpreter interp = new Interpreter();
                interp.correctlySpends( scriptSig, scriptPubKey, new Transaction(), 0 , verifyFlags);

            } catch (ScriptException e) {
                System.err.println(test);
                System.err.flush();
                throw e;
            }
        }
    }

    @Test
    public void dataDrivenInvalidScripts() throws Exception {
        JsonNode json = new ObjectMapper().readTree(new InputStreamReader(getClass().getResourceAsStream(
                "script_invalid.json"), Charsets.UTF_8));
        for (JsonNode test : json) {
            try {
                Script scriptSig = parseScriptString(test.get(0).asText());
                Script scriptPubKey = parseScriptString(test.get(1).asText());
                Set<VerifyFlag> verifyFlags = parseVerifyFlags(test.get(2).asText());

                Interpreter interp = new Interpreter();
                interp.correctlySpends( scriptSig, scriptPubKey, new Transaction(), 0 , verifyFlags);

                System.err.println(test);
                System.err.flush();
                fail();
            } catch (VerificationException e) {
                // Expected.
            }
        }
    }

    @Test
    public void parseKnownAsm() throws IOException {
        String asm = "OP_DUP OP_HASH160 20 0xf4c03610e60ad15100929cc23da2f3a799af1725 OP_EQUALVERIFY OP_CHECKSIG";
        Script script = Script.fromAsmString(asm);
        assertEquals(ScriptOpCodes.OP_DUP, script.getChunks().get(0).opcode);
//        expect(script.chunks[1].opcodenum, equals(OpCodes.OP_HASH160));
//        expect(script.chunks[2].opcodenum, equals(20));
//        expect(HEX.encode(script.chunks[2].buf), equals('f4c03610e60ad15100929cc23da2f3a799af1725'));
//        expect(script.chunks[3].opcodenum, equals(OpCodes.OP_EQUALVERIFY));
//        expect(script.chunks[4].opcodenum, equals(OpCodes.OP_CHECKSIG));
    }

    /*
          test('should parse this known script in ASM', () {
        var asm = 'OP_DUP OP_HASH160 f4c03610e60ad15100929cc23da2f3a799af1725 OP_EQUALVERIFY OP_CHECKSIG';
        var script = SVScript.fromASM(asm);
        expect(script.chunks[0].opcodenum, equals(OpCodes.OP_DUP));
        expect(script.chunks[1].opcodenum, equals(OpCodes.OP_HASH160));
        expect(script.chunks[2].opcodenum, equals(20));
        expect(HEX.encode(script.chunks[2].buf), equals('f4c03610e60ad15100929cc23da2f3a799af1725'));
        expect(script.chunks[3].opcodenum, equals(OpCodes.OP_EQUALVERIFY));
        expect(script.chunks[4].opcodenum, equals(OpCodes.OP_CHECKSIG));
      });

      test('should parse this known problematic script in ASM', () {
        var asm = 'OP_RETURN 026d02 0568656c6c6f';
        var script = SVScript.fromASM(asm);
        expect(script.toString(type:'asm'), equals(asm));
      });

      test('should know this is invalid hex', () {
        var asm = 'OP_RETURN 026d02 0568656c6c6fzz';
        expect(() => SVScript.fromASM(asm), throwsException);
      });

      test('should parse this long PUSHDATA1 script in ASM', () {
        var buf = Uint8List(220);
        var asm = 'OP_RETURN ' + HEX.encode(buf);
        var script = SVScript.fromASM(asm);
        expect(script.chunks[1].opcodenum, equals(OpCodes.OP_PUSHDATA1));
        expect(script.toString(type:'asm'), equals(asm));
      });

      test('should parse this long PUSHDATA2 script in ASM', () {
        var buf = Uint8List(1024);
        var asm = 'OP_RETURN ' + HEX.encode(buf);
        var script = SVScript.fromASM(asm);
        expect(script.chunks[1].opcodenum, equals(OpCodes.OP_PUSHDATA2));
        expect(script.toString(type:'asm'), equals(asm));
      });

      test('should parse this long PUSHDATA4 script in ASM', () {
        var buf = Uint8List(pow(2, 17));
        var asm = 'OP_RETURN ' + HEX.encode(buf);
        var script = SVScript.fromASM(asm);
        expect(script.chunks[1].opcodenum, equals(OpCodes.OP_PUSHDATA4));
        expect(script.toString(type:'asm'), equals(asm));
      });

      test('should return this script correctly - OP_FALSE', () {
        var asm1 = 'OP_FALSE';
        var asm2 = 'OP_0';
        var asm3 = '0';
        expect(SVScript.fromASM(asm1).toString(type:'asm'),equals(asm3));
        expect(SVScript.fromASM(asm2).toString(type:'asm'),equals(asm3));
        expect(SVScript.fromASM(asm3).toString(type:'asm'),equals(asm3));
      });


      test('should return this script correctly - OP_1NEGATE', () {
        var asm1 = 'OP_1NEGATE';
        var asm2 = '-1';
        expect(SVScript.fromASM(asm1).toString(type:'asm'), equals(asm2));
        expect(SVScript.fromASM(asm2).toString(type:'asm'), equals(asm2));
      });


      test('should output this buffer an OP code, data, and another OP code', () {
        var writer = ByteDataWriter();
        writer.writeUint8(OpCodes.OP_0);
        writer.writeUint8(OpCodes.OP_PUSHDATA4);
        writer.writeUint16(3, Endian.little);
        writer.write([0, 0, 1, 2, 3]);
        writer.writeUint8(OpCodes.OP_0);

        var buf = writer.toBytes();
        var script = SVScript.fromBuffer(buf);
        expect(script.chunks.length, equals(3));
        expect(script.chunks[0].opcodenum, equals(buf[0]));
        expect(HEX.encode(script.chunks[1].buf), equals('010203'));
        expect(script.chunks[2].opcodenum, equals(buf[buf.length - 1]));
        expect(script.toString(),  equals('OP_0 OP_PUSHDATA4 3 0x010203 OP_0'));
      });

      test('should output this known script as ASM', () {
        var script = SVScript.fromHex('76a914f4c03610e60ad15100929cc23da2f3a799af172588ac');
        expect(script.toString(type: 'asm'), equals('OP_DUP OP_HASH160 f4c03610e60ad15100929cc23da2f3a799af1725 OP_EQUALVERIFY OP_CHECKSIG'));
      });


      test('should output this known script with pushdata1 opcode as ASM', () {
        // network: livenet
        // txid: dd6fabd2d879be7b8394ad170ff908e9a36b5d5d0b394508df0cca36d2931589
        var script = SVScript.fromHex('00483045022100beb1d83771c04faaeb40bded4f031ed0e0730aaab77cf70102ecd05734a1762002206f168fb00f3b9d7c04b8c78e1fc11e81b9caa49885a904bf22780a7e14a8373101483045022100a319839e37828bf164ff45de34a3fe22d542ebc8297c5d87dbc56fc3068ff9d5022077081a877b6e7f104d8a2fe0985bf2eb7de2e08edbac9499fc3710a353f65461014c69522103a70ae7bde64333461fb88aaafe12ad6c67ca17c8213642469ae191e0aabc7251210344a62338c8ddf138771516d38187146242db50853aa588bcb10a5e49c86421a52102b52a1aed304c4d6cedcf82911f90ca6e1ffed0a5b8f7f19c68213d6fcbde677e53ae');
        expect(script.toString(type:'asm'), equals('0 3045022100beb1d83771c04faaeb40bded4f031ed0e0730aaab77cf70102ecd05734a1762002206f168fb00f3b9d7c04b8c78e1fc11e81b9caa49885a904bf22780a7e14a8373101 3045022100a319839e37828bf164ff45de34a3fe22d542ebc8297c5d87dbc56fc3068ff9d5022077081a877b6e7f104d8a2fe0985bf2eb7de2e08edbac9499fc3710a353f6546101 522103a70ae7bde64333461fb88aaafe12ad6c67ca17c8213642469ae191e0aabc7251210344a62338c8ddf138771516d38187146242db50853aa588bcb10a5e49c86421a52102b52a1aed304c4d6cedcf82911f90ca6e1ffed0a5b8f7f19c68213d6fcbde677e53ae'));
      });

      test('should OP_1NEGATE opcode as -1 with ASM', () {
        var script = SVScript.fromString('OP_1NEGATE');
        expect(script.toString(type: 'asm'), equals('-1'));
      });

     */


}
