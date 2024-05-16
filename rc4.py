from Crypto.Cipher import ARC4
import base64
from argparse import ArgumentParser

# This is a vulnerable implementation of RC4

def enc(key, p):
    return ARC4.new(key.encode('utf-8')).encrypt(p)


def dec(key, c):
    return ARC4.new(key.encode('utf-8')).decrypt(c)


def readFile(fileName):
    with open(fileName, "rb") as infile:
        data = infile.read()
    return data


def writeFile(fileName, data):
    with open(fileName, "wb") as outfile:
        outfile.write(data)
    return data


def main():
    description = """ 
    This is a vulnerable implementation of RC4. The flaw in this implementation is using the same key for all of the encryptions.
    """
    parser = ArgumentParser(description=description)
    parser.add_argument("-pf", "--plaintext-file", help="File to encrypt")
    parser.add_argument("-cf", "--ciphertext-file", help="File to decrypt")
    parser.add_argument("-o", "--output", help="Output file", required=True)

    args = parser.parse_args()

    key = 'WasfyAndCherifVeryLongKeyButStaticOne!!'

    if args.plaintext_file:
        plaintext = readFile(args.plaintext_file)
        encrypted = enc(key, plaintext)
        writeFile(args.output, encrypted)

    elif args.ciphertext_file:
        ciphertext = readFile(args.ciphertext_file)
        decrypted = dec(key, ciphertext)
        writeFile(args.output, decrypted)
        print(decrypted.decode())


if __name__ == '__main__':
    main()
