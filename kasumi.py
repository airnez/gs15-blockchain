#!/usr/bin/env python3

def lecture_bloc(file, bloc_size):
    last_iteration = False

    while  not last_iteration:
        data = file.read(bloc_size)

        if len(data) < bloc_size:
            data = data + b"0"*(bloc_size-len(data))
            last_iteration = True

        yield data

if __name__ == '__main__':

    with open("fichier_clair", "rb") as file:
        for i in lecture_bloc(file, 32):
            print(len(i))
            input()
