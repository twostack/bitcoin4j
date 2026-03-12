package org.twostack.bitcoin4j.script.templates;

import org.junit.Test;
import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.*;

import java.io.IOException;
import java.util.Collections;

import static org.junit.Assert.*;

public class P2SHTemplateTest {

    private final P2SHTemplate template = new P2SHTemplate();

    @Test
    public void matchesP2SHScript() throws IOException {
        Script script = Script.fromBitcoindString("OP_HASH160 20 0x45ea3f9133e7b1cef30ba606f8433f993e41e159 OP_EQUAL");
        assertTrue(template.matches(script));
    }

    @Test
    public void doesNotMatchP2PKHScript() {
        Script script = ScriptBuilder.createP2PKHOutputScript(new org.twostack.bitcoin4j.ECKey());
        assertFalse(template.matches(script));
    }

    @Test
    public void canBeSatisfiedByAlwaysFalse() throws IOException {
        Script script = Script.fromBitcoindString("OP_HASH160 20 0x45ea3f9133e7b1cef30ba606f8433f993e41e159 OP_EQUAL");
        PublicKey key = PublicKey.fromHex("022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da");
        assertFalse(template.canBeSatisfiedBy(Collections.singletonList(key), script));
    }

    @Test
    public void extractsScriptInfo() throws IOException {
        Script script = Script.fromBitcoindString("OP_HASH160 20 0x45ea3f9133e7b1cef30ba606f8433f993e41e159 OP_EQUAL");
        ScriptInfo info = template.extractScriptInfo(script);

        assertTrue(info instanceof P2SHScriptInfo);
        assertEquals("P2SH", info.getType());
        assertArrayEquals(
                Utils.HEX.decode("45ea3f9133e7b1cef30ba606f8433f993e41e159"),
                ((P2SHScriptInfo) info).getScriptHash()
        );
    }

    @Test(expected = ScriptException.class)
    public void extractScriptInfoThrowsForNonP2SH() {
        Script script = ScriptBuilder.createP2PKHOutputScript(new org.twostack.bitcoin4j.ECKey());
        template.extractScriptInfo(script);
    }
}
