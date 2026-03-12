package org.twostack.bitcoin4j.script.templates;

import org.junit.Test;
import org.twostack.bitcoin4j.ECKey;
import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.*;

import java.util.Collections;

import static org.junit.Assert.*;

public class P2PKTemplateTest {

    private final P2PKTemplate template = new P2PKTemplate();

    @Test
    public void matchesP2PKScript() {
        ECKey key = new ECKey();
        Script script = ScriptBuilder.createP2PKOutputScript(key);
        assertTrue(template.matches(script));
    }

    @Test
    public void doesNotMatchP2PKHScript() {
        ECKey key = new ECKey();
        Script script = ScriptBuilder.createP2PKHOutputScript(key);
        assertFalse(template.matches(script));
    }

    @Test
    public void canBeSatisfiedByMatchingKey() {
        ECKey ecKey = new ECKey();
        PublicKey pubKey = PublicKey.fromBytes(ecKey.getPubKey());
        Script script = ScriptBuilder.createP2PKOutputScript(ecKey);

        assertTrue(template.canBeSatisfiedBy(Collections.singletonList(pubKey), script));
    }

    @Test
    public void cannotBeSatisfiedByWrongKey() {
        ECKey ecKey1 = new ECKey();
        ECKey ecKey2 = new ECKey();
        PublicKey pubKey2 = PublicKey.fromBytes(ecKey2.getPubKey());
        Script script = ScriptBuilder.createP2PKOutputScript(ecKey1);

        assertFalse(template.canBeSatisfiedBy(Collections.singletonList(pubKey2), script));
    }

    @Test
    public void extractsScriptInfo() {
        ECKey key = new ECKey();
        Script script = ScriptBuilder.createP2PKOutputScript(key);

        ScriptInfo info = template.extractScriptInfo(script);
        assertTrue(info instanceof P2PKScriptInfo);
        assertEquals("P2PK", info.getType());
        assertArrayEquals(key.getPubKey(), ((P2PKScriptInfo) info).getPublicKey());
    }

    @Test(expected = ScriptException.class)
    public void extractScriptInfoThrowsForNonP2PK() {
        ECKey key = new ECKey();
        Script script = ScriptBuilder.createP2PKHOutputScript(key);
        template.extractScriptInfo(script);
    }
}
