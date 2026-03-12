package org.twostack.bitcoin4j.script.templates;

import org.junit.Test;
import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.*;
import org.twostack.bitcoin4j.transaction.HodlLockBuilder;

import java.math.BigInteger;
import java.util.Collections;

import static org.junit.Assert.*;

public class HodlockerTemplateTest {

    private final HodlockerTemplate template = new HodlockerTemplate();

    private Script buildHodlockerScript(byte[] pubKeyHash, int lockHeight) {
        HodlLockBuilder builder = new HodlLockBuilder(pubKeyHash, BigInteger.valueOf(lockHeight));
        return builder.getLockingScript();
    }

    @Test
    public void matchesHodlockerScript() {
        byte[] pubKeyHash = Utils.HEX.decode("9674af7395592ec5d91573aa8d6557de55f60147");
        Script script = buildHodlockerScript(pubKeyHash, 1000);
        assertTrue(template.matches(script));
    }

    @Test
    public void doesNotMatchP2PKHScript() {
        Script script = ScriptBuilder.createP2PKHOutputScript(new org.twostack.bitcoin4j.ECKey());
        assertFalse(template.matches(script));
    }

    @Test
    public void canBeSatisfiedByMatchingKey() {
        PublicKey pubKey = PublicKey.fromHex("022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da");
        byte[] pubKeyHash = pubKey.getPubKeyHash();
        Script script = buildHodlockerScript(pubKeyHash, 500000);

        assertTrue(template.canBeSatisfiedBy(Collections.singletonList(pubKey), script));
    }

    @Test
    public void cannotBeSatisfiedByWrongKey() {
        byte[] pubKeyHash = Utils.HEX.decode("9674af7395592ec5d91573aa8d6557de55f60147");
        Script script = buildHodlockerScript(pubKeyHash, 1000);

        PublicKey wrongKey = PublicKey.fromHex("03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9");
        assertFalse(template.canBeSatisfiedBy(Collections.singletonList(wrongKey), script));
    }

    @Test
    public void extractsScriptInfo() {
        byte[] pubKeyHash = Utils.HEX.decode("9674af7395592ec5d91573aa8d6557de55f60147");
        Script script = buildHodlockerScript(pubKeyHash, 1000);

        ScriptInfo info = template.extractScriptInfo(script);
        assertTrue(info instanceof HodlockerScriptInfo);

        HodlockerScriptInfo hodlInfo = (HodlockerScriptInfo) info;
        assertEquals("HODLocker", hodlInfo.getType());
        assertArrayEquals(pubKeyHash, hodlInfo.getPubKeyHash());
        assertEquals(BigInteger.valueOf(1000), hodlInfo.getLockHeight());
    }

    @Test(expected = ScriptException.class)
    public void extractScriptInfoThrowsForNonHodlocker() {
        Script script = ScriptBuilder.createP2PKHOutputScript(new org.twostack.bitcoin4j.ECKey());
        template.extractScriptInfo(script);
    }
}
