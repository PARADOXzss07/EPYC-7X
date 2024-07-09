import hashlib
import json
from time import time
from typing import List
from flask import Flask, jsonify, request, render_template
from uuid import uuid4
from urllib.parse import urlparse
import requests
import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding

class Block:
    def __init__(self, index: int, previous_hash: str, timestamp: float, transactions: List[dict], nonce: int = 0):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        """
        Calculates the hash of the block using SHA-256.
        """
        block_contents = {
            'index': self.index,
            'previous_hash': self.previous_hash,
            'timestamp': self.timestamp,
            'transactions': self.transactions,
            'nonce': self.nonce
        }
        block_string = json.dumps(block_contents, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def mine_block(self, difficulty: int) -> None:
        """
        Mines the block using proof-of-work until the hash meets the difficulty criteria.
        """
        while self.hash[:difficulty] != '0' * difficulty:
            self.nonce += 1
            self.hash = self.calculate_hash()

        print(f"Block mined: {self.hash}")

    def has_valid_transactions(self) -> bool:
        """
        Checks if all transactions in the block are valid.
        For simplicity, assumes all transactions are valid in this example.
        """
        return True

    def merkle_root(self) -> str:
        """
        Calculates the Merkle root of transactions for block validation.
        """
        transactions_hash = [tx['hash'] for tx in self.transactions]
        while len(transactions_hash) > 1:
            if len(transactions_hash) % 2 != 0:
                transactions_hash.append(transactions_hash[-1])
            new_hash_list = []
            for i in range(0, len(transactions_hash), 2):
                combined = transactions_hash[i] + transactions_hash[i + 1]
                new_hash = hashlib.sha256(combined.encode()).hexdigest()
                new_hash_list.append(new_hash)
            transactions_hash = new_hash_list
        return transactions_hash[0]

    def __str__(self) -> str:
        """
        String representation of the block.
        """
        return f"Block #{self.index} [Hash: {self.hash}, Previous Hash: {self.previous_hash}, Timestamp: {self.timestamp}, Nonce: {self.nonce}, Transactions: {self.transactions}]"


class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.nodes = set()
        self.create_block(proof=1, previous_hash='0'*64)  # Genesis block
        self.difficulty = 4  # Adjust difficulty as needed

    def create_block(self, proof, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.pending_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1])
        }
        self.pending_transactions = []
        self.chain.append(block)
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while not check_proof:
            hash_operation = hashlib.sha256(
                str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:self.difficulty] == '0' * self.difficulty:
                check_proof = True
            else:
                new_proof += 1
        return new_proof

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def add_transaction(self, sender_wallet, recipient, amount):
        sender_public_key = sender_wallet.get_public_key()
        transaction_data = {
            'sender': sender_public_key,
            'recipient': recipient,
            'amount': amount,
        }
        signature = sender_wallet.sign_transaction(transaction_data)
        if sender_wallet.verify_transaction(transaction_data, signature, sender_public_key):
            self.pending_transactions.append({
                'sender': sender_public_key,
                'recipient': recipient,
                'amount': amount,
                'signature': signature.hex()
            })
            return self.get_previous_block()['index'] + 1
        else:
            return -1  # Transaction failed verification

    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(
                str(proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:self.difficulty] != '0' * self.difficulty:
                return False
            previous_block = block
            block_index += 1
        return True

    def add_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)

    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            response = requests.get(f'http://{node}/get_chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if length > max_length and self.is_chain_valid(chain):
                    max_length = length
                    longest_chain = chain
        if longest_chain:
            self.chain = longest_chain
            return True
        return False


class Wallet:
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def get_public_key(self):
        return self.public_key.public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def sign_transaction(self, transaction_data):
        """
        Signs a transaction data using SHA-256.
        """
        transaction_string = json.dumps(transaction_data, sort_keys=True).encode()
        signature = self.private_key.sign(
            transaction_string,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_transaction(self, transaction_data, signature, public_key):
        """
        Verifies the integrity of a transaction using SHA-256.
        """
        transaction_string = json.dumps(transaction_data, sort_keys=True).encode()
        public_key_obj = rsa.RSAPublicKey.from_pem(public_key.encode())
        try:
            public_key_obj.verify(
                signature,
                transaction_string,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except (ValueError, cryptography.exceptions.InvalidSignature):
            return False


# Instantiate the Flask Node
app = Flask(__name__)

# Generate a globally unique address for this node
node_address = str(uuid4()).replace('-', '')

# Instantiate the Blockchain
blockchain = Blockchain()

# Instantiate a Wallet
wallet = Wallet()

# Create a basic Tkinter GUI
class BlockchainGUI:
    def __init__(self, master):
        self.master = master
        master.title("EPYC-7X Blockchain GUI")

        self.label = tk.Label(master, text="EPYC-7X Blockchain Information")
        self.label.pack()

        self.chain_button = tk.Button(master, text="View Chain", command=self.view_chain)
        self.chain_button.pack()

        self.mine_button = tk.Button(master, text="Mine Block", command=self.mine_block)
        self.mine_button.pack()

        self.add_transaction_button = tk.Button(master, text="Add Transaction", command=self.add_transaction)
        self.add_transaction_button.pack()

        self.validity_button = tk.Button(master, text="Check Validity", command=self.check_validity)
        self.validity_button.pack()

        self.connect_node_button = tk.Button(master, text="Connect Node", command=self.connect_node)
        self.connect_node_button.pack()

        self.replace_chain_button = tk.Button(master, text="Replace Chain", command=self.replace_chain)
        self.replace_chain_button.pack()

    def view_chain(self):
        response = requests.get('http://localhost:5000/get_chain')
        if response.status_code == 200:
            chain = response.json()['chain']
            chain_str = "\n".join([f"Block {block['index']} - Hash: {block['previous_hash']}" for block in chain])
            messagebox.showinfo("EPYC-7X Blockchain", f"Chain Length: {len(chain)}\n\n{chain_str}")
        else:
            messagebox.showerror("Error", "Failed to retrieve blockchain.")

    def mine_block(self):
        response = requests.get('http://localhost:5000/mine_block')
        if response.status_code == 200:
            message = response.json()['message']
            messagebox.showinfo("Mining Block", message)
        else:
            messagebox.showerror("Error", "Failed to mine block.")

    def add_transaction(self):
        recipient = "recipient_address"  # Replace with actual recipient address
        amount = 1  # Replace with actual amount
        response = requests.post('http://localhost:5000/add_transaction', json={
            'sender_wallet': wallet.get_public_key(),
            'recipient': recipient,
            'amount': amount
        })
        if response.status_code == 200:
            message = response.json()['message']
            messagebox.showinfo("Add Transaction", message)
        else:
            messagebox.showerror("Error", "Failed to add transaction.")

    def check_validity(self):
        response = requests.get('http://localhost:5000/is_valid')
        if response.status_code == 200:
            message = response.json()['message']
            messagebox.showinfo("Validity Check", message)
        else:
            messagebox.showerror("Error", "Failed to check validity.")

    def connect_node(self):
        node_address = "node_address"  # Replace with actual node address
        response = requests.post('http://localhost:5000/connect_node', json={'node_address': node_address})
        if response.status_code == 200:
            message = response.json()['message']
            messagebox.showinfo("Connect Node", message)
        else:
            messagebox.showerror("Error", "Failed to connect node.")

    def replace_chain(self):
        response = requests.get('http://localhost:5000/replace_chain')
        if response.status_code == 200:
            message = response.json()['message']
            messagebox.showinfo("Replace Chain", message)
        else:
            messagebox.showerror("Error", "Failed to replace chain.")

def run_flask_app():
    app.run(host='0.0.0.0', port=5000)

def run_gui():
    root = tk.Tk()
    gui = BlockchainGUI(root)
    root.mainloop()

if __name__ == '__main__':
    import threading
    flask_thread = threading.Thread(target=run_flask_app)
    flask_thread.start()

    gui_thread = threading.Thread(target=run_gui)
    gui_thread.start()
