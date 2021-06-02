package org.twostack.bitcoin;

public class PublicKey {

    ECKey key;

    //FIXME: hide the constructor for now to force factory method usage
    private PublicKey(ECKey key){
       this.key = key;
    }

    public static PublicKey fromHex(String encoded) {
       byte[] pubkeyBytes = Utils.HEX.decode(encoded);

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
}
