from bitstring import BitArray
from rc4 import rc4


# returns a 'hash_length_bytes' long hash of given bytearray 'data'
def sponge_hash(data: bytearray, hash_length_bytes=8, iterations=3):
    bit_data = absorb(BitArray(bytes=data), hash_length_bytes * 8, 2 * hash_length_bytes)
    for _ in range(iterations):
        bit_data = rc4_permutation(bit_data)
    return bit_data[:hash_length_bytes * 8].bytes


# First step of sponge hashing
def absorb(bit_data: BitArray, bitrate, byte_capacity):
    state = BitArray('uint:' + str(int(byte_capacity / 8)) + '=0')
    padded_bits = pad(bit_data, bitrate)
    number_of_blocks = int(padded_bits.len / bitrate)
    state[:bitrate] = BitArray('uint:' + str(bitrate) + '=' + str(bitrate))

    for i in range(number_of_blocks):
        position = bitrate * i
        block = BitArray(bin=padded_bits.bin[position:position + bitrate])
        state[:bitrate] = state[:bitrate] ^ block
        state = rc4_permutation(state)
    return state


# RC4-based PRP
def rc4_permutation(bitarray):
    permutation_len = len(bitarray)
    permutation_list = rc4(bitarray.bytes, state_len=len(bitarray)).get_permutation_list()
    output_data = BitArray()
    for i in range(permutation_len):
        output_data.append(BitArray(bin=bitarray.bin[permutation_list[i]]))
    return output_data


# Pads the given Bitarray 'bits' to ensure 'bits.len % bitrate == 0'
def pad(bits, bitrate):
    last_block_len = bits.len % bitrate
    bits.append('uint:' + str(bitrate - last_block_len) + '=0')
    return bits