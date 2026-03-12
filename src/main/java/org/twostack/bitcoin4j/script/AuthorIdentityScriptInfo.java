package org.twostack.bitcoin4j.script;

/**
 * Script info for Author Identity protocol scripts.
 */
public class AuthorIdentityScriptInfo extends ScriptInfo {

    private final String signingAlgorithm;
    private final String publicKey;
    private final String signature;

    public AuthorIdentityScriptInfo(String signingAlgorithm, String publicKey, String signature) {
        super("AuthorIdentity");
        this.signingAlgorithm = signingAlgorithm;
        this.publicKey = publicKey;
        this.signature = signature;
    }

    public String getSigningAlgorithm() {
        return signingAlgorithm;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getSignature() {
        return signature;
    }
}
