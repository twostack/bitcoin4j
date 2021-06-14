package org.twostack.bitcoin4j.params;

import org.twostack.bitcoin4j.exception.AddressFormatException;

import java.util.Arrays;
import java.util.List;


public class NetworkParameters {

    private static int bip32HeaderP2PKHpubTEST = 0x043587cf; // The 4 byte header that serializes in base58 to "tpub".
    private static int bip32HeaderP2PKHprivTEST = 0x04358394; // The 4 byte header that serializes in base58 to "tprv"

    private static int bip32HeaderP2PKHpubMAIN = 0x0488b21e; // The 4 byte header that serializes in base58 to "xpub".
    private static int bip32HeaderP2PKHprivMAIN = 0x0488ade4; // The 4 byte header that serializes in base58 to "xprv"

    private static int DUMPED_PRIVATE_HEADER_MAIN = 128;
    private static int DUMPED_PRIVATE_HEADER_TEST = 239;

    //FIXME: These headers are used for serializing. We don't have TESTNET serialization a.t.m
    /** Returns the 4 byte header for BIP32 wallet P2PKH - public key part. */
    public static int getBip32HeaderP2PKHpub(NetworkType networkType) {

        switch (networkType) {
            case  MAIN:
                return bip32HeaderP2PKHpubMAIN;
            case TEST:
            case REGTEST:
            case SCALINGTEST:
                return bip32HeaderP2PKHpubTEST;
            default:
                return bip32HeaderP2PKHpubMAIN;
        }
    }

    public static int getDumpedPrivateKeyHeader(NetworkType networkType){

            switch (networkType) {
                case  MAIN:
                    return DUMPED_PRIVATE_HEADER_MAIN;
                case TEST:
                case REGTEST:
                case SCALINGTEST:
                    return DUMPED_PRIVATE_HEADER_TEST;
                default:
                    return DUMPED_PRIVATE_HEADER_MAIN;
            }
    }

    /** Returns the 4 byte header for BIP32 wallet P2PKH - private key part. */
    public static int getBip32HeaderP2PKHpriv(NetworkType networkType) {
        switch (networkType) {
            case  MAIN:
                return bip32HeaderP2PKHprivMAIN;
            case TEST:
            case REGTEST:
            case SCALINGTEST:
                return bip32HeaderP2PKHprivTEST;
            default:
                return bip32HeaderP2PKHprivMAIN;
        }

    }



    public static List<NetworkType> getNetworkTypes(int version){
        switch (version) {
            case 0 :
            case 5 :
                return Arrays.asList(NetworkType.MAIN);
            case 111 :
            case 196 :
                return Arrays.asList(NetworkType.TEST, NetworkType.REGTEST, NetworkType.SCALINGTEST);

            default:
                throw new AddressFormatException(version + " is not a valid network type.");
        }
    }

    public static AddressType getAddressType(int version) {
        switch (version) {
            case 0 :
            case 111 :
                return AddressType.PUBKEY_HASH;
            case 5 :
            case 196 :
                return AddressType.SCRIPT_HASH;

            default:
                throw new AddressFormatException(version + " is not a valid address type.");
        }
    }


    public static int getNetworkVersion(NetworkAddressType type) {
        switch (type) {
            case MAIN_P2SH:
                return 5;
            case MAIN_PKH :
                return 0;
            case TEST_P2SH:
                return 196;
            case TEST_PKH :
                return 111;
            default :
                return 0;
        }
    }

    public static NetworkAddressType getNetworkAddressType(int versionByte) {
        switch (versionByte) {
            case 5 :
                return NetworkAddressType.MAIN_P2SH;
            case 0 :
                return NetworkAddressType.MAIN_PKH;
            case 196 :
                return NetworkAddressType.TEST_P2SH;
            case 111 :
                return NetworkAddressType.TEST_PKH;
            default:
                throw new AddressFormatException(versionByte + " is not a valid address version type.");
        }
    }

    public static NetworkType getNetworkType(NetworkAddressType networkAddressType) {

        switch (networkAddressType) {
            case MAIN_P2SH:
            case MAIN_PKH :
                return NetworkType.MAIN;
            case TEST_P2SH:
            case TEST_PKH :
                return NetworkType.TEST;
            default :
                return NetworkType.MAIN;
        }
    }
}
