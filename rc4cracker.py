#! /usr/bin/python
from argparse import ArgumentParser
import sys


def readFile(fileName):
    with open (fileName, "rb") as infile:
        data = infile.read()
    return data


def writeFile(fileName, data):
    with open(fileName, "wb") as outfile:
        outfile.write(data)
    return data


def main():
    description = """ 
    Decrypts RC4 ciphertexts with static keys.
    The arguments need to be files, output is delivered via stdout.
    """
    parser = ArgumentParser(description=description)
    parser.add_argument("-kp", "--known-plaintext", help="Known plaintext file.", required=True)
    parser.add_argument("-kc", "--known-ciphertext", help="Ciphertext derived from known plaintext.", required=True)
    parser.add_argument("-uc", "--unknown-ciphertext", help="Ciphertext you want to decrypt.", required=True)
    args = parser.parse_args()

    knownPlaintext = readFile(args.known_plaintext)
    knownCiphertext = readFile(args.known_ciphertext)
    unknownCiphertext = readFile(args.unknown_ciphertext)

    decrypted = bytearray()
    for i in range(0, len(unknownCiphertext)):
        
        # Retrieves the byte of known plaintext, known ciphertext, and 
        # unknown ciphertext corresponding to the current iteration index i.
        p = knownPlaintext[i % len(knownPlaintext)]
        c1 = knownCiphertext[i % len(knownCiphertext)]
        c2 = unknownCiphertext[i]

        # XORs the bytes of the known plaintext (p), known ciphertext (c1), 
        # and unknown ciphertext (c2) to recover the original plaintext byte.
        decrypted.append(p ^ c1 ^ c2)
        
    sys.stdout.buffer.write(decrypted)


if __name__=='__main__':
	main()
