#include <iostream>
#include <vector>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string>
#include <iomanip>
#include <fstream>

using namespace std;

// Transaction structure
struct Transaction {
    string sender;
    string recipient;
    double amount;
    string signature; // For simplicity, using string for signature representation
};

// Block class
class Block {
public:
    int index;
    string previous_hash;
    time_t timestamp;
    vector<Transaction> transactions;
    string hash;
    int nonce;

    Block(int idx, const string& prev_hash, const vector<Transaction>& txns)
        : index(idx), previous_hash(prev_hash), transactions(txns), nonce(0) {
        timestamp = time(nullptr);
        hash = calculate_hash();
    }

    // Calculate SHA-256 hash of the block
    string calculate_hash() const {
        stringstream ss;
        ss << index << previous_hash << timestamp;
        for (const auto& txn : transactions) {
            ss << txn.sender << txn.recipient << fixed << setprecision(2) << txn.amount;
        }
        ss << nonce;
        
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, ss.str().c_str(), ss.str().size());
        SHA256_Final(hash, &sha256);

        stringstream hash_str;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            hash_str << hex << setw(2) << setfill('0') << (int)hash[i];
        }
        return hash_str.str();
    }

    // Mine the block with proof-of-work
    void mine_block(int difficulty) {
        string target(difficulty, '0'); // Target hash with leading zeros
        while (hash.substr(0, difficulty) != target) {
            nonce++;
            hash = calculate_hash();
        }
        cout << "Block mined: " << hash << endl;
    }
};

// Blockchain class
class Blockchain {
private:
    vector<Block> chain;
    vector<Transaction> pending_transactions;
    int difficulty;

public:
    Blockchain() : difficulty(4) {
        chain.emplace_back(1, "0", vector<Transaction>()); // Genesis block
    }

    // Add a new block to the blockchain
    void add_block(Block& new_block) {
        new_block.mine_block(difficulty);
        chain.push_back(new_block);
        pending_transactions.clear(); // Clear pending transactions after adding block
    }

    // Add a transaction to the pending transactions list
    void add_transaction(const string& sender, const string& recipient, double amount) {
        Transaction new_txn = { sender, recipient, amount, "" }; // For simplicity, signature is not implemented here
        pending_transactions.push_back(new_txn);
    }

    // Validate the blockchain by checking hashes and proof-of-work
    bool is_chain_valid() {
        for (size_t i = 1; i < chain.size(); ++i) {
            Block current_block = chain[i];
            Block previous_block = chain[i - 1];

            // Check if the current block's hash is correct
            if (current_block.hash != current_block.calculate_hash()) {
                return false;
            }

            // Check if the previous hash in the current block matches the hash of the previous block
            if (current_block.previous_hash != previous_block.hash) {
                return false;
            }

            // Check if the proof of work is valid
            string hash_operation = to_string(current_block.nonce * current_block.nonce - previous_block.nonce * previous_block.nonce);
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256_CTX sha256;
            SHA256_Init(&sha256);
            SHA256_Update(&sha256, hash_operation.c_str(), hash_operation.size());
            SHA256_Final(hash, &sha256);

            stringstream hash_str;
            for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                hash_str << hex << setw(2) << setfill('0') << (int)hash[i];
            }
            string hash_str_hex = hash_str.str();

            if (hash_str_hex.substr(0, difficulty) != string(difficulty, '0')) {
                return false;
            }
        }
        return true;
    }

    // Print the blockchain
    void print_chain() {
        for (const auto& block : chain) {
            cout << "Block #" << block.index << " [Hash: " << block.hash << ", Previous Hash: " << block.previous_hash << ", Nonce: " << block.nonce << "]" << endl;
            for (const auto& txn : block.transactions) {
                cout << "  Transaction: " << txn.sender << " -> " << txn.recipient << ": " << fixed << setprecision(2) << txn.amount << endl;
            }
        }
    }
};

// Main function for testing the blockchain
int main() {
    Blockchain epyc_7x_chain;

    cout << "EPYC-7X Blockchain Initialized!" << endl;

    // Add some transactions
    epyc_7x_chain.add_transaction("Alice", "Bob", 2.5);
    epyc_7x_chain.add_transaction("Bob", "Charlie", 1.0);

    // Mine a new block
    Block new_block(2, epyc_7x_chain.get_previous_block().hash, epyc_7x_chain.get_pending_transactions());
    epyc_7x_chain.add_block(new_block);

    // Print the blockchain
    epyc_7x_chain.print_chain();

    // Validate the blockchain
    cout << "Blockchain is valid: " << (epyc_7x_chain.is_chain_valid() ? "true" : "false") << endl;

    return 0;
}
