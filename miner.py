import hashlib
import random
import string
import json
import os
import time
from datetime import datetime
from bit import Key, PrivateKey
from bit.format import bytes_to_wif
from bit.base58 import b58decode_check

class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = 0

    def hash_block(self):
        return hashlib.sha256(
            str(self.index).encode() +
            str(self.timestamp).encode() +
            str(self.data).encode() +
            str(self.previous_hash).encode() +
            str(self.nonce).encode()
        ).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, time.time(), "Genesis Block", "0")
        self.chain.append(genesis_block)

    def get_last_block(self):
        return self.chain[-1]

    def add_block(self, new_block):
        new_block.previous_hash = self.get_last_block().hash_block()
        new_block.nonce = self.proof_of_work(new_block)
        self.chain.append(new_block)

    def proof_of_work(self, block, difficulty=4):
        nonce = 0
        while self.valid_proof(block, nonce, difficulty) is False:
            nonce += 1
        return nonce

    def valid_proof(self, block, nonce, difficulty):
        guess = (str(block.index) + str(block.timestamp) +
                 str(block.data) + str(block.previous_hash) + str(nonce)).encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:difficulty] == '0' * difficulty

class Mining:
    @staticmethod
    def mine_block(previous_block_hash, transactions, difficulty):
        prefix_str = '0' * difficulty
        nonce = 0
        block_hash = Mining.calculate_hash(nonce, previous_block_hash, transactions)
        while block_hash[:difficulty] != prefix_str:
            nonce += 1
            block_hash = Mining.calculate_hash(nonce, previous_block_hash, transactions)
        return nonce, block_hash

    @staticmethod
    def calculate_hash(nonce, previous_block_hash, transactions):
        data = str(nonce) + str(previous_block_hash) + transactions
        return hashlib.sha256(data.encode()).hexdigest()

    @staticmethod
    def generate_transaction_id(length=8):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    @staticmethod
    def generate_wallet_address(length=34):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    @staticmethod
    def validate_base58(address):
        try:
            b58decode_check(address)
            return True
        except ValueError:
            return False

    @staticmethod
    def send_to_wallet(private_key, recipient_address, amount):
        if not Mining.validate_base58(private_key):
            print(f"Invalid private key: {private_key}")
            return None
        if not Mining.validate_base58(recipient_address):
            print(f"Invalid wallet address: {recipient_address}")
            return None
        
        try:
            key = Key(private_key)
            tx_hash = key.send([(recipient_address, amount, 'btc')])
            return tx_hash
        except Exception as e:
            print(f"Error in sending transaction: {e}")
            return None

    @staticmethod
    def start(user_wallet, private_key):
        if not Mining.validate_base58(private_key):
            print("Invalid private key format.")
            return
        if not Mining.validate_base58(user_wallet):
            print("Invalid wallet address format.")
            return
        
        previous_block_hash = '0000000000000000000000000000000000000000000000000000000000000000'
        target = 'mining/mining.txt'
        
        if not os.path.exists(target):
            open(target, 'w').close()  # Create the file if it does not exist
        
        with open(target, 'r') as file:
            hashes = file.readlines()

        for has in hashes:
            transaction = {
                "transaction_id": Mining.generate_transaction_id(),
                "sender": Mining.generate_wallet_address(),
                "recipient": user_wallet,
                "amount": round(random.uniform(0.1, 10.0), 2),
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            transactions = json.dumps(transaction)
            difficulty = 4
            nonce, block_hash = Mining.mine_block(previous_block_hash, transactions, difficulty)

            print(f"Hash Received! Nonce: {nonce}, Block Hash: {block_hash}")

            # Kirim hasil penambangan ke dompet
            tx_hash = Mining.send_to_wallet(private_key, user_wallet, transaction['amount'])
            if tx_hash:
                print(f"Transaksi dikirim dengan hash: {tx_hash}")
            else:
                print("Transaksi gagal dikirim.")

if __name__ == '__main__':
    wallet = input("WALLET ADDRESS: ")
    private_key = input("PRIVATE KEY: ")
    Mining.start(wallet, private_key)
    try:
        os.mkdir('mining')
    except FileExistsError:
        pass

    blockchain = Blockchain()
    t = 5000
    for i in range(int(t)):
        new_block = Block(i+1, time.time(), f"Block {i+1}", "")
        blockchain.add_block(new_block)
        print(f"Block {i+1} mined successfully.")
        print("\nBlockchain:")
        for block in blockchain.chain:
            print("Timestamp:", block.timestamp)
            print("Previous Hash:", block.previous_hash)
            print("Block Hash:", block.hash_block())
            print()
