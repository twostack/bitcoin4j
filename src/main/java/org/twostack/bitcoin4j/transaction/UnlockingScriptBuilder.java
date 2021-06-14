
/*
 * Copyright 2021 Stephan M. February
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.twostack.bitcoin4j.transaction;

import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptBuilder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

abstract class UnlockingScriptBuilder {

    List<TransactionSignature> signatures = new ArrayList<>();

    protected Script script;

    UnlockingScriptBuilder(Script script){
        this.script = script;
    }

    UnlockingScriptBuilder(){
        this.script = new ScriptBuilder().build();
    }

    public abstract Script getScriptSig();

    public List<TransactionSignature> getSignatures() {
        return Collections.unmodifiableList(signatures);
    }

    public void addSignature(TransactionSignature signature) {
        this.signatures.add(signature);
    }

}
