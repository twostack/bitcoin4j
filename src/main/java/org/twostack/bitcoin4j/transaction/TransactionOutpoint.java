
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

import java.math.BigInteger;
import java.util.Objects;

/**
 * This is more traditionally referred to as a UTXO. The Transaction Outpoint is a convenience
 * POJO that ties together information from the Transaction Output we are spending from .
 *
 * A TransactionOutput datastructure by itself does not contain all this information.
 *
 */
public class TransactionOutpoint {

    private String transactionId;
    private Integer outputIndex;
    private BigInteger satoshis;
    private Script lockingScript;

    public String getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public Integer getOutputIndex() {
        return outputIndex;
    }

    public void setOutputIndex(Integer outputIndex) {
        this.outputIndex = outputIndex;
    }

    public BigInteger getSatoshis() {
        return satoshis;
    }

    public void setSatoshis(BigInteger satoshis) {
        this.satoshis = satoshis;
    }

    public Script getLockingScript() {
        return lockingScript;
    }

    public void setLockingScript(Script lockingScript) {
        this.lockingScript = lockingScript;
    }

   TransactionOutpoint(String transactionId, Integer outputIndex, BigInteger satoshis, Script lockingScript){
      this.transactionId = transactionId;
      this.outputIndex = outputIndex;
      this.satoshis  = satoshis;
      this.lockingScript = lockingScript;
   }
   TransactionOutpoint(){ }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TransactionOutpoint outpoint = (TransactionOutpoint) o;
        return transactionId.equals(outpoint.transactionId) && outputIndex.equals(outpoint.outputIndex) && satoshis.equals(outpoint.satoshis) && Objects.equals(lockingScript, outpoint.lockingScript);
    }

    @Override
    public int hashCode() {
        return Objects.hash(transactionId, outputIndex, satoshis, lockingScript);
    }
}
