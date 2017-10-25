package scrooge.coin;

import java.security.PublicKey;
import java.util.HashSet;
import java.util.Set;

public class TxHandler {

    private final UTXOPool utxoPool;
    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        if (utxoPool == null)
            throw new IllegalArgumentException("The value of utxoPool could not be null.");

        this.utxoPool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool,
     * (2) the signatures on each input of {@code tx} are valid,
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        if (tx == null)
            throw new IllegalArgumentException("The value of transaction could not be null");

        TransactionValidator validator = new TransactionValidator(this.utxoPool);

        return validator.validationTransaction(tx);
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        // IMPLEMENT THIS
        return new Transaction[0];
    }

    private final class TransactionValidator {

        private final UTXOPool utxoPool;

        public TransactionValidator(UTXOPool utxoPool) {
            if (utxoPool == null)
                throw new IllegalArgumentException("The value of utxoPool could not be null.");

            this.utxoPool = utxoPool;
        }

        public boolean validationTransaction(Transaction transaction) {
            if (transaction == null)
                throw new IllegalArgumentException("The value of transaction could not be null");

            return verifyClaimedOutputs(transaction)
                    && verifyInputSignatures(transaction)
                    && verifyDoubleSpendingAbsence(transaction)
                    && verifyTransactionOutputValues(transaction)
                    && verifyTransactionBalance(transaction);
        }

        // rule #1
        private boolean verifyClaimedOutputs(Transaction transaction) {
            for (int i = 0; i < transaction.numInputs(); ++i) {
                UTXO claimedOutput = getClaimedOutput(transaction, i);

                if (!this.utxoPool.contains(claimedOutput)) {
                    return false;
                }
            }

            return true;
        }

        // rule #2
        private boolean verifyInputSignatures(Transaction transaction) {
            for (int i = 0; i < transaction.numInputs(); ++i) {
                Transaction.Input input = transaction.getInput(i);

                UTXO claimedOutput = new UTXO(input.prevTxHash, input.outputIndex);

                Transaction.Output connectedOutput = this.utxoPool.getTxOutput(claimedOutput);

                PublicKey publicKey = connectedOutput.address;
                byte[] message = transaction.getRawDataToSign(i);
                byte[] signature = input.signature;

                if (!Crypto.verifySignature(publicKey, message, signature)) {
                    return false;
                }
            }

            return true;
        }

        // rule #4
        private boolean verifyTransactionOutputValues(Transaction transaction) {
            for (Transaction.Output output : transaction.getOutputs()) {
                if (output.value < 0) {
                    return false;
                }
            }

            return true;
        }

        // rule #3
        private boolean verifyDoubleSpendingAbsence(Transaction transaction) {
            HashSet<UTXO> spentOutputs = new HashSet<>();

            for (int i = 0; i < transaction.numInputs(); ++i) {
                UTXO claimedOutput = getClaimedOutput(transaction, i);

                if (spentOutputs.contains(claimedOutput)) {
                    return false;
                }

                spentOutputs.add(claimedOutput);
            }

            return true;
        }

        // rule #5
        private boolean verifyTransactionBalance(Transaction transaction) {
            double outputSum = 0;
            for (Transaction.Output output : transaction.getOutputs()) {
                outputSum += output.value;
            }

            double inputSum = 0;

            for (int i = 0; i < transaction.numInputs(); ++i) {
                UTXO claimedOutput = getClaimedOutput(transaction, i);

                Transaction.Output connectedOutput = this.utxoPool.getTxOutput(claimedOutput);

                inputSum += connectedOutput.value;
            }

            return inputSum >= outputSum;
        }

        private UTXO getClaimedOutput(Transaction transaction, int inputIndex) {
            Transaction.Input input = transaction.getInput(inputIndex);

            UTXO claimedOutput = new UTXO(input.prevTxHash, input.outputIndex);

            return claimedOutput;
        }
    }

}
