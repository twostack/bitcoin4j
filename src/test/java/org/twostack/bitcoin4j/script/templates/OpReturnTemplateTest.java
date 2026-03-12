package org.twostack.bitcoin4j.script.templates;

import org.junit.Test;
import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.*;

import java.util.Collections;

import static org.junit.Assert.*;

public class OpReturnTemplateTest {

    private final OpReturnTemplate template = new OpReturnTemplate();

    @Test
    public void matchesOpReturnScript() {
        Script script = ScriptBuilder.createOpReturnScript(new byte[]{0x01, 0x02, 0x03});
        assertTrue(template.matches(script));
    }

    @Test
    public void matchesOpFalseOpReturnScript() {
        ScriptBuilder builder = new ScriptBuilder();
        builder.op(ScriptOpCodes.OP_FALSE);
        builder.op(ScriptOpCodes.OP_RETURN);
        builder.data(new byte[]{0x01, 0x02});
        Script script = builder.build();
        assertTrue(template.matches(script));
    }

    @Test
    public void doesNotMatchP2PKHScript() {
        Script script = ScriptBuilder.createP2PKHOutputScript(new org.twostack.bitcoin4j.ECKey());
        assertFalse(template.matches(script));
    }

    @Test
    public void canBeSatisfiedByAlwaysFalse() {
        Script script = ScriptBuilder.createOpReturnScript(new byte[]{0x01});
        PublicKey key = PublicKey.fromHex("022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da");
        assertFalse(template.canBeSatisfiedBy(Collections.singletonList(key), script));
    }

    @Test
    public void extractsScriptInfoFromOpReturn() {
        Script script = ScriptBuilder.createOpReturnScript(new byte[]{0x01, 0x02, 0x03});
        ScriptInfo info = template.extractScriptInfo(script);

        assertTrue(info instanceof OpReturnScriptInfo);
        assertEquals("OP_RETURN", info.getType());
        OpReturnScriptInfo opInfo = (OpReturnScriptInfo) info;
        assertEquals(1, opInfo.getDataChunks().size());
        assertArrayEquals(new byte[]{0x01, 0x02, 0x03}, opInfo.getDataChunks().get(0));
    }

    @Test
    public void extractsScriptInfoFromOpFalseOpReturn() {
        ScriptBuilder builder = new ScriptBuilder();
        builder.op(ScriptOpCodes.OP_FALSE);
        builder.op(ScriptOpCodes.OP_RETURN);
        builder.data(new byte[]{(byte) 0xCA, (byte) 0xFE});
        builder.data(new byte[]{(byte) 0xBE, (byte) 0xEF});
        Script script = builder.build();

        ScriptInfo info = template.extractScriptInfo(script);
        assertTrue(info instanceof OpReturnScriptInfo);
        OpReturnScriptInfo opInfo = (OpReturnScriptInfo) info;
        assertEquals(2, opInfo.getDataChunks().size());
    }

    @Test(expected = ScriptException.class)
    public void extractScriptInfoThrowsForNonOpReturn() {
        Script script = ScriptBuilder.createP2PKHOutputScript(new org.twostack.bitcoin4j.ECKey());
        template.extractScriptInfo(script);
    }
}
