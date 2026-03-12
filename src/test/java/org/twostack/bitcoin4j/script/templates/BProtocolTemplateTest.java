package org.twostack.bitcoin4j.script.templates;

import org.junit.Test;
import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.*;

import java.nio.charset.StandardCharsets;
import java.util.Collections;

import static org.junit.Assert.*;

public class BProtocolTemplateTest {

    private final BProtocolTemplate template = new BProtocolTemplate();

    private Script buildBProtocolScript() {
        ScriptBuilder builder = new ScriptBuilder();
        builder.op(ScriptOpCodes.OP_FALSE);
        builder.op(ScriptOpCodes.OP_RETURN);
        builder.data(BProtocolTemplate.B_PROTOCOL_PREFIX.getBytes(StandardCharsets.UTF_8));
        builder.data("Hello World".getBytes(StandardCharsets.UTF_8)); // data
        builder.data("text/plain".getBytes(StandardCharsets.UTF_8)); // media type
        builder.data("UTF-8".getBytes(StandardCharsets.UTF_8)); // encoding
        builder.data("hello.txt".getBytes(StandardCharsets.UTF_8)); // filename
        return builder.build();
    }

    @Test
    public void matchesBProtocolScript() {
        assertTrue(template.matches(buildBProtocolScript()));
    }

    @Test
    public void doesNotMatchP2PKHScript() {
        Script script = ScriptBuilder.createP2PKHOutputScript(new org.twostack.bitcoin4j.ECKey());
        assertFalse(template.matches(script));
    }

    @Test
    public void doesNotMatchDifferentOpReturnPrefix() {
        ScriptBuilder builder = new ScriptBuilder();
        builder.op(ScriptOpCodes.OP_FALSE);
        builder.op(ScriptOpCodes.OP_RETURN);
        builder.data("SomeOtherPrefix".getBytes(StandardCharsets.UTF_8));
        builder.data("data".getBytes(StandardCharsets.UTF_8));
        builder.data("text/plain".getBytes(StandardCharsets.UTF_8));
        assertFalse(template.matches(builder.build()));
    }

    @Test
    public void canBeSatisfiedByAlwaysFalse() {
        PublicKey key = PublicKey.fromHex("022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da");
        assertFalse(template.canBeSatisfiedBy(Collections.singletonList(key), buildBProtocolScript()));
    }

    @Test
    public void extractsScriptInfo() {
        ScriptInfo info = template.extractScriptInfo(buildBProtocolScript());

        assertTrue(info instanceof BProtocolScriptInfo);
        BProtocolScriptInfo bInfo = (BProtocolScriptInfo) info;
        assertEquals("BProtocol", bInfo.getType());
        assertArrayEquals("Hello World".getBytes(StandardCharsets.UTF_8), bInfo.getData());
        assertEquals("text/plain", bInfo.getMediaType());
        assertEquals("UTF-8", bInfo.getEncoding());
        assertEquals("hello.txt", bInfo.getFilename());
    }

    @Test
    public void extractsScriptInfoWithOptionalFieldsMissing() {
        ScriptBuilder builder = new ScriptBuilder();
        builder.op(ScriptOpCodes.OP_FALSE);
        builder.op(ScriptOpCodes.OP_RETURN);
        builder.data(BProtocolTemplate.B_PROTOCOL_PREFIX.getBytes(StandardCharsets.UTF_8));
        builder.data("data".getBytes(StandardCharsets.UTF_8));
        builder.data("image/png".getBytes(StandardCharsets.UTF_8));
        Script script = builder.build();

        ScriptInfo info = template.extractScriptInfo(script);
        assertTrue(info instanceof BProtocolScriptInfo);
        BProtocolScriptInfo bInfo = (BProtocolScriptInfo) info;
        assertEquals("image/png", bInfo.getMediaType());
        assertNull(bInfo.getEncoding());
        assertNull(bInfo.getFilename());
    }

    @Test(expected = ScriptException.class)
    public void extractScriptInfoThrowsForNonBProtocol() {
        Script script = ScriptBuilder.createP2PKHOutputScript(new org.twostack.bitcoin4j.ECKey());
        template.extractScriptInfo(script);
    }
}
