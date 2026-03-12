package org.twostack.bitcoin4j.script.templates;

import org.junit.Test;
import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.*;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;

public class P2MSTemplateTest {

    private final P2MSTemplate template = new P2MSTemplate();

    private final String key1Hex = "022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da";
    private final String key2Hex = "03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9";
    private final String key3Hex = "021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18";

    private Script buildMultisigScript() throws IOException {
        return Script.fromBitcoindString(
                "OP_2 33 0x" + key1Hex + " 33 0x" + key2Hex + " 33 0x" + key3Hex + " OP_3 OP_CHECKMULTISIG");
    }

    @Test
    public void matchesMultisigScript() throws IOException {
        assertTrue(template.matches(buildMultisigScript()));
    }

    @Test
    public void doesNotMatchP2PKHScript() {
        Script script = ScriptBuilder.createP2PKHOutputScript(new org.twostack.bitcoin4j.ECKey());
        assertFalse(template.matches(script));
    }

    @Test
    public void canBeSatisfiedByEnoughKeys() throws IOException {
        Script script = buildMultisigScript();
        PublicKey pk1 = PublicKey.fromHex(key1Hex);
        PublicKey pk2 = PublicKey.fromHex(key2Hex);

        assertTrue(template.canBeSatisfiedBy(Arrays.asList(pk1, pk2), script));
    }

    @Test
    public void cannotBeSatisfiedByInsufficientKeys() throws IOException {
        Script script = buildMultisigScript();
        PublicKey pk1 = PublicKey.fromHex(key1Hex);

        assertFalse(template.canBeSatisfiedBy(Collections.singletonList(pk1), script));
    }

    @Test
    public void extractsScriptInfo() throws IOException {
        Script script = buildMultisigScript();
        ScriptInfo info = template.extractScriptInfo(script);

        assertTrue(info instanceof P2MSScriptInfo);
        P2MSScriptInfo msInfo = (P2MSScriptInfo) info;
        assertEquals("P2MS", msInfo.getType());
        assertEquals(2, msInfo.getThreshold());
        assertEquals(3, msInfo.getTotalKeys());
        assertEquals(3, msInfo.getPublicKeys().size());
    }

    @Test(expected = ScriptException.class)
    public void extractScriptInfoThrowsForNonMultisig() {
        Script script = ScriptBuilder.createP2PKHOutputScript(new org.twostack.bitcoin4j.ECKey());
        template.extractScriptInfo(script);
    }
}
