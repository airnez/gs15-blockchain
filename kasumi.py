#!/usr/bin/env python3

import random

BLOC_SIZE_BYTES = 8

KEY_BIT_SIZE = 128

NOTHING_UP_NUMBER = 0x123456789ABCDEFFEDCBA9876543210


S_BOX_1 = [187,  67,  47,   2, 159, 168, 194,  29, 168, 241,  29,  65,  36,
        95,  85, 240,  84, 252,  58, 172, 223, 232, 216, 106,  62,  41,
       159,   1, 212, 239, 199,  91,   9,  97, 112, 214, 138, 136, 185,
        51,  72,  87, 103, 210, 132, 103, 223,  59, 139,  86, 146,  23,
        69, 150, 128,  54,  30, 127, 206, 205,   2, 245,  12,  93,  59,
       222,  41,   3,  94,  17,   7,  57,  11, 242, 142,   2,  71, 190,
       195,  81, 209,  99,  92,  42,  93, 181, 218,  42, 218, 162, 206,
       168, 243, 206, 225, 101, 171, 133, 119, 242, 172, 107,   2, 210,
        66, 172, 163,  35,  57,  25, 213, 242, 235,  53,  96,  25,  48,
       123,   7, 234,  86, 167, 244, 134,  96, 233, 103,  58, 212, 203,
        43,  58,  44,  25,  78,  14, 100, 183, 242, 147,  56,  24, 162,
       188,  80, 222, 127,  87,  30,   0,  89,  86,  93,  54,   7, 184,
       195,   2,  95, 226,  31,  81, 119, 122, 246, 231, 158, 160,  27,
       104, 104,  42, 103, 236, 184,  38, 173, 102,  41,  97,  61, 241,
       228, 143, 209,  42, 115, 242,  72, 156, 151, 197, 149,  54, 110,
       239, 239,  46, 131,  27, 106, 191,  75, 255,  94, 228, 232, 238,
         3,  23,   8, 184, 206,  70, 119, 215,  64, 226,  52, 114, 114,
       182, 172, 223, 205, 152, 206,  22, 246, 248, 109,  30,  93, 162,
       116, 112,   7, 185,   9,  90, 178, 178, 186,  22,   4,  76,  64,
       168,  67,  15, 169, 102,  61, 138, 239, 234]

S_BOX_2 = [187,  97,  53, 139, 159,  88,   6, 174, 251, 115, 118, 237, 187,
       195, 131,  49, 139, 165, 228, 123,  98,  53, 155, 190, 163,  48,
        93,  73,  10,  28, 116, 156,  57, 119, 178,  86,  85, 193,  43,
       164,  60,  94, 114, 129,  60,   3, 144, 198, 109, 172, 175, 204,
       228, 107, 165,   7, 121,  62,  43,  76, 121, 168,  77, 247, 231,
        69,  69,  54, 104, 107, 225, 219, 101,  62,  60,  83,  32,   8,
       240,  46, 178, 188,  27, 134, 187, 195,  67,   8,  38,  20, 243,
       251, 175, 112,  43,  44, 251,  83, 190, 234, 175,  45, 155,  31,
       162, 214,  35, 121, 178,  75,   9,  75, 119, 160,  41,  77, 201,
        12, 227, 204, 228, 177, 235, 236,  12,  53,  88, 115, 172, 239,
       117, 196, 103,  52,  22, 162,  63, 128,  42,  81, 152,  90, 215,
       192, 182, 100, 150, 107, 166,  59, 253,  23, 235, 177, 218, 167,
       192,  86,  23, 131, 185,  23,  23, 138, 196, 176,  87, 127,  79,
       155, 104, 161, 194, 189,  57,  43,  67, 162,  90, 174, 204, 252,
        72, 151, 231,  31, 107,  20, 173,  42, 136, 120,  98,  76, 156,
       157, 132,  61,  29, 128,  49, 182,  69, 245, 104, 243,  93, 147,
       240,  56,  86,  96, 186, 133, 136, 214, 235,  20, 238, 235, 185,
       111, 253, 161, 240, 207, 224, 132, 203, 133, 166,  45,   6,  45,
        85, 201, 178, 247, 231, 165, 104, 243, 139, 181,  23, 206, 210,
       137, 216,  47, 127,  89, 115, 102, 116,  49]


"""
    : encode :
        : encode les str vers bytes, avec utf8 à défaut

    : decode :
        decode des bytes, vers utf8 à défaut


    > plus facile de travailler avec les bits sous
    forme d'entiers que de bytes (car pas d'opérations entre bytes)


    > vaux mieux bosser en little endian
        : permet d'avoir a[0] : octet LSB


    > iteration ; de 0 à 7,
        donc inverse fonctions Fi, entre pair et impair
"""



"""
    générer avec RC4, clé de 128 bits

"""
def generate_keys():
    key = random.randint(2**(KEY_BIT_SIZE-1), 2**KEY_BIT_SIZE-1)
    modifed_key = key ^ NOTHING_UP_NUMBER

    return key, modifed_key

def take_sub_key(key, sub_key_index):
    key = key.to_bytes(KEY_BIT_SIZE//8, "little")
    key = key[(sub_key_index)*2 : (sub_key_index+1)*2]
    key = int.from_bytes(key, "little")

    return key

"""
    iteration : de 0 à 7
"""
def generate_sub_key(key, modified_key, iteration):

    keys_dict = {}

    keys_dict["KL_i_1"] = left_shift( take_sub_key(key, iteration), 1)
    keys_dict["KL_i_2"] = take_sub_key(modified_key, (iteration+2)%8 )

    keys_dict["KO_i_1"] = left_shift( take_sub_key(key, (iteration+1)%8) , 5)
    keys_dict["KO_i_1"] = left_shift( take_sub_key(key, (iteration+5)%8), 8)
    keys_dict["KO_i_3"] = left_shift( take_sub_key(key, (iteration+6)%8), 13)

    keys_dict["KI_i_1"] = take_sub_key(modified_key, (iteration+4)%8)
    keys_dict["KI_i_2"] = take_sub_key(modified_key, (iteration+3)%8)
    keys_dict["KI_i_3"] = take_sub_key(modified_key, (iteration+7)%8)

    return keys_dict

def right_shift(int, i):
    length = int.bit_length()

    result = ( int >> i) | (( int & (2** i - 1)) << (length - i))
    return result

def left_shift(int, i):
    length = int.bit_length()

    result = (int & (2**(length - i) - 1) ) << i  | (int >> (length - i))
    return result

def lecture_bloc(file, byte_bloc_size):
    last_iteration = False

    while  not last_iteration:
        data = file.read(byte_bloc_size)

        if data == b"":
            break

        yield data

def FI(y, z):

    z_bytes = z.to_bytes(2, "little")
    z_1 = z_bytes[0]
    z_2 = z_bytes[1]

    z_1 = S_BOX_1[z_1]
    z_2 = S_BOX_2[z_2]

    z = z_2.to_bytes(1,"little") + z_1.to_bytes(1,"little")
    z = int.from_bytes(z, "little")

    x = right_shift(y, 2) ^ (z)

    return x





if __name__ == '__main__':
    """
    with open("fichier_clair", "rb") as file:
        for i in lecture_bloc(file, BLOC_SIZE_BYTES):
            print(bin(int.from_bytes(i, "big")))
            break"""

    key, modifed_key = generate_keys()

    for i in range(0,8):
        a = generate_sub_key(key, modifed_key, i)
        for j in a.keys():
            print(a[j].bit_length())


        input()
