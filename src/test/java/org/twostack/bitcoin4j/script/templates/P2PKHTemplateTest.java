package org.twostack.bitcoin4j.script.templates;

import org.junit.Test;
import org.twostack.bitcoin4j.ECKey;
import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.*;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.*;

public class P2PKHTemplateTest {

    private final P2PKHTemplate template = new P2PKHTemplate();

    @Test
    public void matchesP2PKHScript() {
        ECKey key = new ECKey();
        Script script = ScriptBuilder.createP2PKHOutputScript(key);
        assertTrue(template.matches(script));
    }

    @Test
    public void doesNotMatchP2PKScript() {
        ECKey key = new ECKey();
        Script script = ScriptBuilder.createP2PKOutputScript(key);
        assertFalse(template.matches(script));
    }

    @Test
    public void doesNotMatchOpReturnScript() {
        Script script = ScriptBuilder.createOpReturnScript(new byte[]{0x01});
        assertFalse(template.matches(script));
    }

    @Test
    public void canBeSatisfiedByMatchingKey() {
        ECKey ecKey = new ECKey();
        PublicKey pubKey = PublicKey.fromBytes(ecKey.getPubKey());
        Script script = ScriptBuilder.createP2PKHOutputScript(ecKey);

        assertTrue(template.canBeSatisfiedBy(Collections.singletonList(pubKey), script));
    }

    @Test
    public void cannotBeSatisfiedByWrongKey() {
        ECKey ecKey1 = new ECKey();
        ECKey ecKey2 = new ECKey();
        PublicKey pubKey2 = PublicKey.fromBytes(ecKey2.getPubKey());
        Script script = ScriptBuilder.createP2PKHOutputScript(ecKey1);

        assertFalse(template.canBeSatisfiedBy(Collections.singletonList(pubKey2), script));
    }

    @Test
    public void cannotBeSatisfiedByEmptyKeys() {
        ECKey key = new ECKey();
        Script script = ScriptBuilder.createP2PKHOutputScript(key);
        assertFalse(template.canBeSatisfiedBy(Collections.emptyList(), script));
    }

    @Test
    public void extractsScriptInfo() {
        ECKey key = new ECKey();
        Script script = ScriptBuilder.createP2PKHOutputScript(key);

        ScriptInfo info = template.extractScriptInfo(script);
        assertTrue(info instanceof P2PKHScriptInfo);
        assertEquals("P2PKH", info.getType());
        assertArrayEquals(key.getPubKeyHash(), ((P2PKHScriptInfo) info).getPubKeyHash());
    }

    @Test(expected = ScriptException.class)
    public void extractScriptInfoThrowsForNonP2PKH() {
        ECKey key = new ECKey();
        Script script = ScriptBuilder.createP2PKOutputScript(key);
        template.extractScriptInfo(script);
    }
}
