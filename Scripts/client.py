# Client to implement simplified RSA algorithm.
# The client says hello to the server, and the server responds with a Hello
# and its public key. The client then sends a session key encrypted with the
# server's public key. The server responds to this message with a nonce
# encrypted with the server's public key. The client decrypts the nonce
# and sends it back to the server encrypted with the session key. Finally,
# the server sends the client a message with a status code.
# Author: Odain Chevannes 2015-11-13

#!/usr/bin/python3

import socket
import math
import random
import simplified_AES

def expMod(base, power, n):
    """"Returns base^power mod(n)"""
    exponent = 1
    i = 0
    while i < power:
        exponent *= base
        i += 1
    return exponent%n

def RSAencrypt(m, e, n):
    """Encryption side of RSA"""
    # Write code to do RSA encryption
    cipher = expMod(m,e,n)
    return cipher

def RSAdecrypt(c, d, n):
    """Decryption side of RSA"""
    # Write code to RSA decryption
    plaintext = expMod(c,d,n)
    return plaintext

def serverHello():
    """Sends server hello message"""
    status = "100 Hello"
    return status

def sendSessionKey(s):
    """Sends server session key"""
    status = "112 SessionKey " + str(s)
    return status

def sendTransformedNonce(xform):
    """Sends server nonce encrypted with session key"""
    status = "130 " + str(xform)
    return status

def computeSessionKey():
    """Computes this node's session key"""
    sessionKey = random.randint(1, 32768)
    return sessionKey
    


def main():
    """Driver function for the project"""
    HOST = 'localhost'        # The remote host
    PORT = 13000               # The same port as used by the server
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.connect((HOST,PORT))
    msg = serverHello()
    c.sendall(bytes(msg,'utf-8'))  # Sending bytes encoded in utf-8 format.
    data = c.recv(1024).decode('utf-8')
    strStatus = "105 Hello"
    if data and data.find(strStatus) < 0:
        print("Invalid data received. Closing")
    else:
        # Write appropriate code to parse received string and extract
        # the modulus and exponent for public key encryption.
        splitd = data.split(" ")
        n = int(splitd[2])# Modulus for public key encryption
        e = int(splitd[3]) # Exponent for public key encryption
        print("Server's public key: ("+ str(n)+","+str(e)+")")
        symmetricKey = computeSessionKey()
        print("the generated symm key is ",symmetricKey)
        simplified_AES.keyExp(symmetricKey)
        encSymmKey = RSAencrypt(symmetricKey, e, n)
        print("encrypted symm key ",encSymmKey)
        msg = sendSessionKey(encSymmKey)
        c.sendall(bytes(msg,'utf-8'))
        data = c.recv(1024).decode('utf-8')
        strStatus = "113 Nonce"
        if data and data.find(strStatus) < 0:
            print("Invalid data received. Closing")
        else:
            # Write code to parse received string and extract encrypted nonce
            splitd = data.split(" ")
            encNonce = int(splitd[2])
            # from the server. The nonce has been encrypted with the server's
            # private key.
            print("Encrypted nonce: "+ str(encNonce))
            temp = RSAencrypt(encNonce, e, n)
            plaintext = temp
            print("Decrypted nonce: "+ str(temp))
            """Setting up for Simplified AES encryption"""
            simplified_AES.keyExp(symmetricKey) # Generating round keys for AES.
            ciphertext = simplified_AES.encrypt(plaintext) # Running simplified AES.
            msg = sendTransformedNonce(ciphertext)
            c.sendall(bytes(msg,'utf-8'))
            data = c.recv(1024).decode('utf-8')
            if data:
                print(data)
    c.close()

if __name__ == "__main__":
    main()
