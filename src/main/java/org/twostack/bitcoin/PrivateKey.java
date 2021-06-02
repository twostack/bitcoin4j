package org.twostack.bitcoin;

import org.twostack.bitcoin.address.Base58;
import org.twostack.bitcoin.exception.InvalidKeyException;
import org.twostack.bitcoin.params.NetworkType;
import org.twostack.bitcoin.transaction.ReadUtils;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public class PrivateKey {

    ECKey key;
    boolean _hasCompressedPubKey;
    NetworkType _networkType;

    public PrivateKey(ECKey key){
        this(key, true, NetworkType.MAIN);
    }

    public PrivateKey(ECKey key, boolean isCompressed, NetworkType networkType) {
        this.key = key;
        this._hasCompressedPubKey = isCompressed;
        this._networkType = networkType;
    }

    public static PrivateKey fromWIF(String wif) throws InvalidKeyException {

        boolean isCompressed = false;

        if (wif.length() != 51 && wif.length() != 52){
            throw new InvalidKeyException("Valid keys are either 51 or 52 bytes in length");
        }

        //decode from base58
        byte[] versionAndDataBytes = Base58.decodeChecked(wif);

        NetworkType networkType = decodeNetworkType(wif);

        //strip first byte
        ReadUtils reader = new ReadUtils(versionAndDataBytes);
        byte version = reader.readByte();
        byte[] dataBytes = reader.readBytes(versionAndDataBytes.length - 1);

        byte[] keyBytes = dataBytes.clone();
        if (dataBytes.length == 33){
            //drop last byte
            //throw error if last byte is not 0x01 to indicate compression
            if (dataBytes[32] != 0x01) {
                throw new InvalidKeyException("Compressed keys must have last byte set as 0x01. Yours is [" + dataBytes[32] + "]");
            }

            keyBytes = new ReadUtils(dataBytes).readBytes(32);
            isCompressed = true;
        }

        String keyHex = Utils.HEX.encode(keyBytes);
        BigInteger d = new BigInteger(keyHex, 16);

        ECKey key = ECKey.fromPrivate(d);

        return new PrivateKey(key, isCompressed, networkType);
    }


    private static NetworkType decodeNetworkType(String wifKey) throws InvalidKeyException{

        switch (wifKey.charAt(0)){
            case '5' : {
                if (wifKey.length() != 51) {
                    throw new InvalidKeyException("Uncompressed private keys have a length of 51 bytes");
                }

                return NetworkType.MAIN;
            }
            case '9' : {
                if (wifKey.length() != 51) {
                    throw new InvalidKeyException("Uncompressed private keys have a length of 51 bytes");
                }

                return NetworkType.TEST;
            }
            case 'L' : case 'K' : {
                if (wifKey.length() != 52) {
                    throw new InvalidKeyException("Compressed private keys have a length of 52 bytes");
                }

                return NetworkType.MAIN;
            }
            case 'c' : {
                if (wifKey.length() != 52) {
                    throw new InvalidKeyException("Compressed private keys have a length of 52 bytes");
                }

                return NetworkType.TEST;
            }
            default : {
                throw new InvalidKeyException("Address WIF format must start with either [5] , [9], [L], [K] or [c]");
            }

        }
    }

    public PublicKey getPublicKey() {
        return PublicKey.fromHex(Utils.HEX.encode(key.getPubKey()));
    }
}
