package org.twostack.bitcoin4j.script;

import org.junit.Test;
import org.twostack.bitcoin4j.ECKey;
import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.templates.*;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;

public class ScriptTemplateRegistryTest {

    @Test
    public void registryIsSingleton() {
        ScriptTemplateRegistry reg1 = ScriptTemplateRegistry.getInstance();
        ScriptTemplateRegistry reg2 = ScriptTemplateRegistry.getInstance();
        assertSame(reg1, reg2);
    }

    @Test
    public void canLookupTemplateByName() {
        ScriptTemplateRegistry registry = ScriptTemplateRegistry.getInstance();
        assertNotNull(registry.getTemplate("P2PKH"));
        assertNotNull(registry.getTemplate("P2PK"));
        assertNotNull(registry.getTemplate("P2MS"));
        assertNotNull(registry.getTemplate("P2SH"));
        assertNotNull(registry.getTemplate("OP_RETURN"));
        assertNotNull(registry.getTemplate("HODLocker"));
        assertNotNull(registry.getTemplate("AuthorIdentity"));
        assertNotNull(registry.getTemplate("BProtocol"));
        assertNull(registry.getTemplate("NonExistent"));
    }

    @Test
    public void identifiesP2PKHScript() {
        ECKey key = new ECKey();
        Script script = ScriptBuilder.createP2PKHOutputScript(key);

        ScriptTemplateRegistry registry = ScriptTemplateRegistry.getInstance();
        ScriptTemplate template = registry.identifyScript(script);

        assertNotNull(template);
        assertEquals("P2PKH", template.getName());
    }

    @Test
    public void identifiesP2PKScript() {
        ECKey key = new ECKey();
        Script script = ScriptBuilder.createP2PKOutputScript(key);

        ScriptTemplateRegistry registry = ScriptTemplateRegistry.getInstance();
        ScriptTemplate template = registry.identifyScript(script);

        assertNotNull(template);
        assertEquals("P2PK", template.getName());
    }

    @Test
    public void identifiesOpReturnScript() {
        Script script = ScriptBuilder.createOpReturnScript(new byte[]{0x01, 0x02, 0x03});

        ScriptTemplateRegistry registry = ScriptTemplateRegistry.getInstance();
        ScriptTemplate template = registry.identifyScript(script);

        assertNotNull(template);
        assertEquals("OP_RETURN", template.getName());
    }

    @Test
    public void extractsP2PKHScriptInfo() {
        ECKey key = new ECKey();
        Script script = ScriptBuilder.createP2PKHOutputScript(key);

        ScriptTemplateRegistry registry = ScriptTemplateRegistry.getInstance();
        ScriptInfo info = registry.extractScriptInfo(script);

        assertNotNull(info);
        assertEquals("P2PKH", info.getType());
        assertTrue(info instanceof P2PKHScriptInfo);
        assertArrayEquals(key.getPubKeyHash(), ((P2PKHScriptInfo) info).getPubKeyHash());
    }

    @Test
    public void returnsNullForUnknownScript() {
        // Build a script that doesn't match any template
        Script script = new ScriptBuilder()
                .op(ScriptOpCodes.OP_NOP)
                .op(ScriptOpCodes.OP_NOP)
                .build();

        ScriptTemplateRegistry registry = ScriptTemplateRegistry.getInstance();
        assertNull(registry.identifyScript(script));
        assertNull(registry.extractScriptInfo(script));
    }

    @Test
    public void identifiesP2SHScript() throws IOException {
        Script script = Script.fromBitcoindString("OP_HASH160 20 0x45ea3f9133e7b1cef30ba606f8433f993e41e159 OP_EQUAL");

        ScriptTemplateRegistry registry = ScriptTemplateRegistry.getInstance();
        ScriptTemplate template = registry.identifyScript(script);

        assertNotNull(template);
        assertEquals("P2SH", template.getName());
    }

    @Test
    public void identifiesMultisigScript() throws IOException {
        Script script = Script.fromBitcoindString(
                "OP_2 33 0x022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da " +
                "33 0x03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9 " +
                "33 0x021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18 " +
                "OP_3 OP_CHECKMULTISIG");

        ScriptTemplateRegistry registry = ScriptTemplateRegistry.getInstance();
        ScriptTemplate template = registry.identifyScript(script);

        assertNotNull(template);
        assertEquals("P2MS", template.getName());
    }

    @Test
    public void identifiesHodlockerScript() {
        // Build a HODLocker script: <lockHeight> CLTV DROP DUP HASH160 <hash> EQUALVERIFY CHECKSIG
        byte[] pubKeyHash = Utils.HEX.decode("9674af7395592ec5d91573aa8d6557de55f60147");
        ScriptBuilder builder = new ScriptBuilder();
        builder.data(new byte[]{(byte) 0xe8, 0x03}); // 1000 in little-endian
        builder.op(ScriptOpCodes.OP_CHECKLOCKTIMEVERIFY);
        builder.op(ScriptOpCodes.OP_DROP);
        builder.op(ScriptOpCodes.OP_DUP);
        builder.op(ScriptOpCodes.OP_HASH160);
        builder.data(pubKeyHash);
        builder.op(ScriptOpCodes.OP_EQUALVERIFY);
        builder.op(ScriptOpCodes.OP_CHECKSIG);
        Script script = builder.build();

        ScriptTemplateRegistry registry = ScriptTemplateRegistry.getInstance();
        ScriptTemplate template = registry.identifyScript(script);

        assertNotNull(template);
        assertEquals("HODLocker", template.getName());
    }

    @Test
    public void registersCustomTemplate() {
        ScriptTemplateRegistry registry = ScriptTemplateRegistry.getInstance();

        ScriptTemplate custom = new ScriptTemplate() {
            @Override
            public String getName() { return "CustomTest"; }
            @Override
            public boolean matches(Script script) { return false; }
            @Override
            public boolean canBeSatisfiedBy(List<PublicKey> keys, Script script) { return false; }
            @Override
            public ScriptInfo extractScriptInfo(Script script) { return null; }
        };

        registry.register(custom);
        assertSame(custom, registry.getTemplate("CustomTest"));
    }
}
