package org.twostack.bitcoin.params;

import org.twostack.bitcoin.exception.AddressFormatException;

import java.util.Arrays;
import java.util.List;

import static org.twostack.bitcoin.params.NetworkAddressType.*;


public class NetworkParameters {

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
}
