
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
package org.twostack.bitcoin4j;

public class PublicKey {


    private ECKey key;

    //FIXME: hide the constructor for now to force factory method usage
    private PublicKey(ECKey key){
       this.key = key;
    }

    public static PublicKey fromHex(String encoded) {
       byte[] pubkeyBytes = Utils.HEX.decode(encoded);

       return new PublicKey(ECKey.fromPublicOnly(pubkeyBytes));
    }

    public static PublicKey fromBytes(byte[] pubkeyBytes){
        return new PublicKey(ECKey.fromPublicOnly(pubkeyBytes));
    }

    public byte[] getPubKeyHash(){
        return key.getPubKeyHash();
    }

    public byte[] getPubKeyBytes(){
        return key.getPubKey();
    }

    public String getPubKeyHex(){
        return key.getPublicKeyAsHex();
    }

    public ECKey getKey() {
        return key;
    }
}
