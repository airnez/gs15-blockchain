import math


class rc4:
    def __init__(self, key, state_len=256):
        self.S = list(range(state_len))
        self.x = 0
        self.y = 0

        j = 0
        for i in range(len(self.S)):
            j = (j + self.S[i] + key[i % (len(key))]) % len(self.S)
            self.S[i], self.S[j] = self.S[j], self.S[i]

    # returns a single pseudo-random int
    def get_byte(self):
        self.x = (self.x + 1) % len(self.S)
        self.y = (self.y + self.S[self.x]) % len(self.S)
        self.S[self.x], self.S[self.y] = self.S[self.y], self.S[self.x]
        return self.S[(self.S[self.x] + self.S[self.y]) % len(self.S)]

    # returns a generated pseudo-random int array of given length
    def get_bytes(self, length):
        output = []
        for i in range(length):
            output.append(self.get_byte())
        return output

    # cipher/decipher a bytes message
    def cipher(self, message):
        output = bytearray()
        for i in range(len(message)):
            output.append(self.get_byte() ^ message[i])
        return output

    # returns S, a pseudo random permutation order list of state_len (arg given at object instantiation)
    def get_permutation_list(self):
        return self.S

'''
#exemple
key_string = 'secretKey'
message_string = 'secretMessage'
RC4_INPUT_KEY = key_string.encode('utf-8')
RC4_INPUT_MESSAGE = message_string.encode('utf-8')

rc4_sender = rc4(RC4_INPUT_KEY)
encrypted = rc4_sender.cipher(RC4_INPUT_MESSAGE)
print(encrypted.hex())

rc4_receiver = rc4(RC4_INPUT_KEY)
clear_message = rc4_receiver.cipher(encrypted)
print(clear_message.decode('utf-8'))
'''