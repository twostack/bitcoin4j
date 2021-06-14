package org.twostack.bitcoin4j.transaction;

public enum TransactionOption {

    // When serializing the transaction to hexadecimal it is possible
    // to selectively disable some checks. See [Transaction.serialize()]
    // Disables all checks
    DISABLE_ALL,

    ///  Disables checking if the transaction spends more bitcoins than the sum of the input amounts
    DISABLE_MORE_OUTPUT_THAN_INPUT,

    ///  Disables checking for fees that are too large
    DISABLE_LARGE_FEES,

    ///  Disables checking if there are no outputs that are dust amounts
    DISABLE_DUST_OUTPUTS,

    ///  Disables checking if all inputs are fully signed
    DISABLE_FULLY_SIGNED

}
