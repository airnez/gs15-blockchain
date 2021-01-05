from bitstring import BitArray
import json
from spongeHash import sponge_hash

DIFFICULTY = 8
BLOC_SIZE = 10


class Transaction:
    def __init__(self, debit_user_id: str, credit_user_id: str, transaction_value: float, signature: str):
        self.debit_user_id = debit_user_id
        self.credit_user_id = credit_user_id
        self.transaction_value = transaction_value
        self.signature = signature

    # TODO: handle transaction verification
    def verify(self):
        return True

    def serialize(self):
        return {
            'debit_user_id': self.debit_user_id,
            'credit_user_id': self.credit_user_id,
            'transaction_value': self.transaction_value,
            'signature': self.signature
        }

    @staticmethod
    def deserialize(data):
        return Transaction(data['debit_user_id'], data['credit_user_id'], data['transaction_value'], data['signature'])


class Block:
    def __init__(self, block_number: int, previous_hash: str):
        self.transactions = []
        self.number = block_number
        self.previous_hash = previous_hash
        self.salt = ''

    # adds a transaction to the block
    def add_transaction(self, new_transaction: Transaction):
        self.transactions.append(new_transaction)

    def serialize(self):
        return {
            'transactions': [t.serialize() for t in self.transactions],
            'number': self.number,
            'previous_hash': self.previous_hash,
            'salt': self.salt
        }

    @staticmethod
    def deserialize(data):
        block = Block(data['number'], data['previous_hash'])
        block.salt = data['salt']
        for t in data['transactions']:
            block.add_transaction(Transaction.deserialize(t))
        return block

    # Returns the computed block's hash
    def hash(self):
        return BitArray(bytes=sponge_hash(json.dumps(self.serialize()).encode()))

    # [0] returns true if the block's hash fits the difficult
    # [1] returns the computed hash
    def verify_salt(self):
        pattern_to_match = "0" * DIFFICULTY
        computed_hash = self.hash()
        return computed_hash[-DIFFICULTY:].bin == pattern_to_match, computed_hash

    # Verifies the block integrity regarding its salt and previous block hash
    def verify(self, previous_hash):
        return previous_hash == self.previous_hash and self.verify_salt()[0]

    # Computes the salt matching the required difficulty
    def mine(self):
        i = 0
        verified, computed_hash = self.verify_salt()
        while not verified:
            self.salt = i
            verified, computed_hash = self.verify_salt()
            i += 1
        print('block ' + str(self.number) + ' mined with salt ' + str(self.salt) + ' and hash ' + computed_hash.hex)
        return computed_hash


class Blockchain:
    def __init__(self):
        self.chain = []

    # Mines the existing block and creates a new one
    def increment(self):
        old_block = self.chain[-1]
        new_block_number = old_block.number + 1
        print('Incrementing chain from bloc ' + str(new_block_number - 1) + ' to ' + str(new_block_number))
        previous_hash = old_block.mine()
        new_block = Block(new_block_number, previous_hash)
        self.chain.append(new_block)

    # Adds a transaction to the chain and increments the chain if needed
    def add_transaction(self, transaction: Transaction):
        if len(self.chain[-1].transactions) >= BLOC_SIZE:
            self.increment()
        block = self.chain[-1]
        block.add_transaction(transaction)

    # Adds a block to the chain
    def add_block(self, new_block: Block):
        self.chain.append(new_block)

    # Saves the blockchain on the given file path
    def save(self, saving_file_path: str):
        with open(saving_file_path, "w") as write_file:
            json.dump({'chain': [b.serialize() for b in self.chain]}, fp=write_file)

    # Returns a blockchain object from the given file path
    @staticmethod
    def load(file_path: str):
        with open(file_path, 'r') as read_file:
            loaded_data = json.load(read_file)
            chain = loaded_data['chain']
            blockchain = Blockchain()
            for b in chain:
                blockchain.add_block(Block.deserialize(b))
        return blockchain

    # Verifies the integrity of the whole chain
    def verify(self):
        verified = True
        previous_hash = self.chain[0].previous_hash
        for block in self.chain:
            verified = verified and block.verify(previous_hash)
            previous_hash = block.hash().hex
            if not verified:
                print(block.number)
                break
        return verified
