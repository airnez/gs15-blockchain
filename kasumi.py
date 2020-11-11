#!/usr/bin/env python3

def lecture_bloc(file, bloc_size):
    while  True:
        data = file.read(bloc_size)

        if len(data) < bloc_size:
            data = data + b"0"*(bloc_size-len(data))

        if data == b'':
            break

        yield data

if __name__ == '__main__':

    with open("fichier_clair", "rb") as file:
        for i in test(file, 32):
            print(i)
            input()
