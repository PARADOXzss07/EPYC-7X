#define CROW_MAIN
#include "crow_all.h"
#include <string>
#include <vector>
#include <ctime>
#include <map>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

using namespace std;

// Utility functions for RSA key generation, signing, and verification
void generate_key_pair(string& public_key, string& private_key) {
    EVP_PKEY* pkey = EVP_PKEY_new();
    RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
    EVP_PKEY_assign_RSA(pkey, rsa);

    BIO* pub = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(pub, pkey);
    size_t pub_len = BIO_pending(pub);
    public_key.resize(pub_len);
    BIO_read(pub, &public_key[0], pub_len);
    BIO_free_all(pub);

    BIO* pri = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(pri, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    size_t pri_len = BIO_pending(pri);
    private_key.resize(pri_len);
    BIO_read(pri, &private_key[0], pri_len);
    BIO_free_all(pri);

    EVP_PKEY_free(pkey);
}

string sign_transaction(const string& data, const string& private_key) {
    EVP_PKEY* pkey = EVP_PKEY_new();
    BIO* pri = BIO_new_mem_buf(private_key.data(), -1);
    PEM_read_bio_PrivateKey(pri, &pkey, nullptr, nullptr);
    BIO_free(pri);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey);
    EVP_DigestSignUpdate(ctx, data.data(), data.size());

    size_t sig_len;
    EVP_DigestSignFinal(ctx, nullptr, &sig_len);
    string signature(sig_len, '\0');
    EVP_DigestSignFinal(ctx, (unsigned char*)&signature[0], &sig_len);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return signature;
}

bool verify_transaction(const string& data, const string& signature, const string& public_key) {
    EVP_PKEY* pkey = EVP_PKEY_new();
    BIO* pub = BIO_new_mem_buf(public_key.data(), -1);
    PEM_read_bio_PUBKEY(pub, &pkey, nullptr, nullptr);
    BIO_free(pub);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey);
    EVP_DigestVerifyUpdate(ctx, data.data(), data.size());

    bool result = EVP_DigestVerifyFinal(ctx, (unsigned char*)signature.data(), signature.size()) == 1;

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return result;
}

// Transaction structure
struct Transaction {
    string sender;
    string recipient;
    double amount;
    string signature;

    string to_string() const {
        stringstream ss;
        ss << sender << recipient << fixed << setprecision(2) << amount;
        return ss.str();
    }

    bool is_valid(const string& public_key) const {
        return verify_transaction(to_string(), signature, public_key);
    }
};

// Wallet class
class Wallet {
public:
    string public_key;
    string private_key;

    Wallet() {
        generate_key_pair(public_key, private_key);
    }

    string sign_transaction(const Transaction& txn) const {
        return ::sign_transaction(txn.to_string(), private_key);
    }
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
    }

    bool has_valid_transactions(const map<string, Wallet>& wallets) const {
        for (const auto& txn : transactions) {
            auto it = wallets.find(txn.sender);
            if (it == wallets.end() || !txn.is_valid(it->second.public_key)) {
                return false;
            }
        }
        return true;
    }
};

// Blockchain class
class Blockchain {
private:
    vector<Block> chain;
    vector<Transaction> pending_transactions;
    int difficulty;
    map<string, Wallet> wallets;

public:
    Blockchain() {
        difficulty = 4; // Initial mining difficulty
        chain.emplace_back(Block(0, "0", {})); // Genesis block
    }

    Wallet& create_wallet() {
        Wallet wallet;
        wallets[wallet.public_key] = wallet;
        return wallets[wallet.public_key];
    }

    void add_transaction(const string& sender, const string& recipient, double amount, const string& signature) {
        Transaction txn{sender, recipient, amount, signature};
        auto it = wallets.find(sender);
        if (it != wallets.end() && txn.is_valid(it->second.public_key)) {
            pending_transactions.push_back(txn);
        } else {
            cout << "Invalid transaction signature" << endl;
        }
    }

    void add_block(Block& block) {
        if (block.has_valid_transactions(wallets)) {
            block.mine_block(difficulty);
            chain.push_back(block);
            pending_transactions.clear();
        } else {
            cout << "Block contains invalid transactions" << endl;
        }
    }

    const Block& get_previous_block() const {
        return chain.back();
    }

    const vector<Transaction>& get_pending_transactions() const {
        return pending_transactions;
    }

    bool is_chain_valid() const {
        for (size_t i = 1; i < chain.size(); ++i) {
            const Block& current_block = chain[i];
            const Block& previous_block = chain[i - 1];

            if (current_block.hash != current_block.calculate_hash()) {
                return false;
            }
            if (current_block.previous_hash != previous_block.hash) {
                return false;
            }
            if (!current_block.has_valid_transactions(wallets)) {
                return false;
            }
        }
        return true;
    }

    void print_chain() const {
        for (const auto& block : chain) {
            cout << "Block #" << block.index << " [Hash: " << block.hash << ", Previous Hash: " << block.previous_hash << ", Nonce: " << block.nonce << "]" << endl;
            for (const auto& txn : block.transactions) {
                cout << "  Transaction: " << txn.sender << " -> " << txn.recipient << ": " << fixed << setprecision(2) << txn.amount << endl;
            }
        }
    }
};

int main() {
    Blockchain epyc_7x_chain;

    crow::SimpleApp app;

    CROW_ROUTE(app, "/")([]() {
        return crow::mustache::load("index.html").render();
    });

    CROW_ROUTE(app, "/create
