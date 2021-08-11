package org.twostack.bitcoin4j.exception;

import org.twostack.bitcoin4j.script.ScriptError;

public class SignatureEncodingException extends  Exception{
    ScriptError err;

    public SignatureEncodingException() {super();}

    public SignatureEncodingException(String message){super(message);}

    public SignatureEncodingException(ScriptError err, String message){
        super(message);
        this.err = err;

    }

    public ScriptError getErr() {
        return err;
    }
}
