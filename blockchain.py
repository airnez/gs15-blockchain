from bitstring import BitArray
import json
from copy import copy

from signature import El_Gamal_Signature, RSA_Signature, check_El_Gamal_Signature, check_RSA_signature
from spongeHash import sponge_hash

DIFFICULTY = 8
BLOC_SIZE = 10


def get_user_public_key(user_public_signature):
    if user_public_signature['signature_type'] == 'El_gamal':
        return user_public_signature['p'] + user_public_signature['alpha'] + user_public_signature['h']
    elif user_public_signature['signature_type'] == 'RSA':
        return user_public_signature['n'] + user_public_signature['e']


class Transaction:
    def __init__(self, debit_user_public_key, credit_user_public_key,
                 transaction_value: float, signature=None):
        self.debit_user_public_key = debit_user_public_key
        self.credit_user_public_key = credit_user_public_key
        self.transaction_value = transaction_value
        self.signature = signature

    def verify(self):
        transaction_copy = copy(self)
        transaction_copy.signature = None
        serialized_copy = transaction_copy.serialize()
        if self.signature is None:
            return False
        elif self.signature['signature_type'] == 'El_gamal':
            return check_El_Gamal_Signature(p=self.signature['p'], signature=self.signature['signature'],
                                            message=json.dumps(serialized_copy), alpha=self.signature['alpha'],
                                            h=self.signature['h'])
        elif self.signature['signature_type'] == 'RSA':
            return check_RSA_signature(e=self.signature['e'], n=self.signature['n'],
                                       signature=self.signature['signature'], message=json.dumps(serialized_copy))
        return False

    # returns the signature and generates it if necessary
    def sign(self, debit_user_private_signature, signature_type='El_gamal'):
        if self.signature is None:
            if signature_type == 'El_gamal':
                p, alpha, h, x = debit_user_private_signature['p', 'alpha', 'h', 'x']
                self.signature = {'signature': El_Gamal_Signature(p=p, x=x, h=h, alpha=alpha,
                                                                  message=json.dumps(self.serialize())),
                                  'signature_type': signature_type,
                                  'p': p,
                                  'alpha': alpha,
                                  'h': h}

            elif signature_type == 'RSA':
                n, e, d = debit_user_private_signature['n, e, d']
                self.signature = {'signature': RSA_Signature(n=n, d=d,
                                                             message=json.dumps(self.serialize())),
                                  'signature_type': signature_type,
                                  'e': e,
                                  'n': n}
        else:
            print('Transaction already signed !')
        return self.signature

    def serialize(self):
        return {
            'debit_user_public_key': self.debit_user_public_key,
            'credit_user_public_key': self.credit_user_public_key,
            'transaction_value': self.transaction_value,
            'signature': self.signature,
        }

    @staticmethod
    def deserialize(data):
        return Transaction(data['debit_user_public_key'],
                           data['credit_user_public_key'],
                           data['transaction_value'],
                           data['signature'])


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
    def verify(self, previous_hash, signature_type):
        transactions_verified = True
        for transaction in self.transactions:
            transactions_verified = transactions_verified and transaction.verify() \
                                    and transaction.signature['type'] == signature_type
            if not transactions_verified:
                print('Faulty transaction in block ' + str(self.number) + ' : ' + json.dumps(transaction.serialize()))

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
    def __init__(self, signature_type='El_gamal'):
        self.chain = []
        self.signature_type = signature_type

    # Mines the existing block and creates a new one
    def increment(self):
        old_block = self.chain[-1]
        new_block_number = old_block.number + 1
        print('Incrementing chain from bloc ' + str(new_block_number - 1) + ' to ' + str(new_block_number))
        previous_hash = old_block.mine()
        new_block = Block(new_block_number, previous_hash)
        self.chain.append(new_block)

    def init(self):
        first_block = Block(0, 'init_block')
        self.add_block(first_block)

    # Adds a transaction to the chain and increments the chain if needed
    def add_transaction(self, transaction: Transaction):
        if len(self.chain) == 0:
            self.init()
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
            json.dump({'chain': [b.serialize() for b in self.chain],
                       'signature_type': self.signature_type}, fp=write_file)

    # Returns a blockchain object from the given file path
    @staticmethod
    def load(file_path: str):
        with open(file_path, 'r') as read_file:
            loaded_data = json.load(read_file)
            chain = loaded_data['chain']
            blockchain = Blockchain(loaded_data['signature_type'])
            for b in chain:
                blockchain.add_block(Block.deserialize(b))
        return blockchain

    # Verifies the integrity of the whole chain
    def verify(self):
        verified = True
        previous_hash = self.chain[0].previous_hash
        for block in self.chain:
            verified = verified and block.verify(previous_hash, self.signature_type)
            previous_hash = block.hash().hex
            if not verified:
                print('Chain rupture here: block ' + str(block.number))
                break
        return verified
