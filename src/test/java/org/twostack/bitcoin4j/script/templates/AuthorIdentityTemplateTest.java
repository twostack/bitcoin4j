package org.twostack.bitcoin4j.script.templates;

import org.junit.Test;
import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.*;

import java.nio.charset.StandardCharsets;
import java.util.Collections;

import static org.junit.Assert.*;

public class AuthorIdentityTemplateTest {

    private final AuthorIdentityTemplate template = new AuthorIdentityTemplate();

    private Script buildAuthorIdentityScript() {
        ScriptBuilder builder = new ScriptBuilder();
        builder.op(ScriptOpCodes.OP_FALSE);
        builder.op(ScriptOpCodes.OP_RETURN);
        builder.data(AuthorIdentityTemplate.AUTHOR_IDENTITY_PREFIX.getBytes(StandardCharsets.UTF_8));
        builder.data("BITCOIN_ECDSA".getBytes(StandardCharsets.UTF_8));
        builder.data("02abc123def456".getBytes(StandardCharsets.UTF_8));
        builder.data("304402200abc...".getBytes(StandardCharsets.UTF_8));
        return builder.build();
    }

    @Test
    public void matchesAuthorIdentityScript() {
        assertTrue(template.matches(buildAuthorIdentityScript()));
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
        assertFalse(template.matches(builder.build()));
    }

    @Test
    public void canBeSatisfiedByAlwaysFalse() {
        PublicKey key = PublicKey.fromHex("022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da");
        assertFalse(template.canBeSatisfiedBy(Collections.singletonList(key), buildAuthorIdentityScript()));
    }

    @Test
    public void extractsScriptInfo() {
        ScriptInfo info = template.extractScriptInfo(buildAuthorIdentityScript());

        assertTrue(info instanceof AuthorIdentityScriptInfo);
        AuthorIdentityScriptInfo aiInfo = (AuthorIdentityScriptInfo) info;
        assertEquals("AuthorIdentity", aiInfo.getType());
        assertEquals("BITCOIN_ECDSA", aiInfo.getSigningAlgorithm());
        assertEquals("02abc123def456", aiInfo.getPublicKey());
        assertEquals("304402200abc...", aiInfo.getSignature());
    }

    @Test(expected = ScriptException.class)
    public void extractScriptInfoThrowsForNonAuthorIdentity() {
        Script script = ScriptBuilder.createP2PKHOutputScript(new org.twostack.bitcoin4j.ECKey());
        template.extractScriptInfo(script);
    }
}
