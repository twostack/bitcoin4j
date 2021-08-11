package org.twostack.bitcoin4j.exception;

import org.twostack.bitcoin4j.script.ScriptError;

public class PubKeyEncodingException extends Exception{

    ScriptError err;

    public PubKeyEncodingException() {super();}

    public PubKeyEncodingException(String message) {super(message);}

    public PubKeyEncodingException(ScriptError err, String message){
        super(message);
        this.err = err;
    }

    public ScriptError getErr() {
        return err;
    }
}
