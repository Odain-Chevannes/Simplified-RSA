# Server to implement simplified RSA algorithm.
# The server waits for the client to say Hello. Once the client says hello,
# the server sends the client a public key. The client uses the public key to
# send a session key with confidentiality to the server. The server then sends
# a nonce (number used once) to the client, encrypted with the server's private
# key. The client decrypts that nonce and sends it back to server encrypted
# with the session key.

# Author: Odain Chevannes 2015-11-13

#!/usr/bin/python3

import socket
import random
import math
import hashlib
import time
import sys
import simplified_AES

def expMod(base, power, n):
  exponent = 1
  i = 0
  while i < power:
    exponent *= base
    i += 1
  return exponent%n
	      
def RSAencrypt(m, e, n):
    """Encryption side of RSA"""
    # Fill in the code to do RSA encryption
    cipher = expMod(m,e,n)
    return cipher

def RSAdecrypt(c, d, n):
    """Decryption side of RSA"""
    # Fill in the code to do RSA decryption
    plaintext = expMod(c,d,n)
    return plaintext

def gcd_iter(u, v):
    """Iterative Euclidean algorithm"""
    while v:
        u, v = v, u % v
    return abs(u)
  
def ext_Euclid(a, p):
    '''
    The multiplicitive inverse of a in the integers modulo p.
    Return b s.t.
    a * b == 1 mod p
    '''
    
    for d in range(1, p):
        r = (d * a) % p
        if r == 1:
            break
    else:
        raise ValueError('%d has no inverse mod %d' % (a, p))
    return d

def generateNonce():
    """This method returns a 16-bit random integer derived from hashing the
    current time. This is used to test for liveness"""
    hash = hashlib.sha1()
    hash.update(str(time.time()).encode('utf-8'))
    return int.from_bytes(hash.digest()[:2], byteorder=sys.byteorder)

def genKeys(p, q):
    """Generate n, phi(n), e, and d."""
    n  = p*q
    phi_of_n = (p-1)*(q-1)
    e = 0
    
    #find a e less than n that is coprime with phi(n)
    count=2
    while count:
        gcd = gcd_iter(phi_of_n,count)
        if gcd==1:
            e = count
            break
        count+=1
        
    # finding the mutiplicative inverse of e and phi(n)
    d = ext_Euclid(e,phi_of_n)

    #positive values of d
    if d<0:
      d = phi_of_n - d
    return n,e,d

def clientHelloResp(n, e):
    """Responds to client's hello message with modulus and exponent"""
    status = "105 Hello "+ str(n) + " " + str(e)
    return status

def SessionKeyResp(nonce):
    """Responds to session key with nonce"""
    status = "113 Nonce "+ str(nonce)
    return status

def nonceVerification(nonce, decryptedNonce):
    """Verifies that the transmitted nonce matches that received
       from the client."""
    if nonce == decryptedNonce:
        return "200 OK"
    else:
        return "400 Error Detected"
    

HOST = ''                 # Symbolic name meaning all available interfaces
PORT = 13000               # Arbitrary non-privileged port
strHello = "100 Hello"
strHelloResp = "105 Hello"
strSessionKey = "112 SessionKey"
strSessionKeyResp = "113 Nonce"
strNonceResp = "130"
strServerStatus = ""
print ("Enter prime numbers. One should be between 907 and 1013, and the other\
 between 53 and 67")
p = int(input('Enter P : '))
q = int(input('Enter Q: '))

n, e, d = genKeys(p, q)
print("n,e,d",n,e,d)
#create an INET, STREAMing socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#bind the socket to a public host,
# and a well-known port
s.bind((HOST, PORT))
#become a server socket
s.listen(1)

while True:
    conn, addr = s.accept()
    print("Server is Running...")
    print('Connected by', addr)


    data = conn.recv(1024).decode('utf-8')
    if data and data.find(strHello) >= 0:
        msg = clientHelloResp(n, e)
        conn.sendall(bytes(msg, 'utf-8'))
        data = conn.recv(1024).decode('utf-8')
        #print("encrypted symm key ",data) //test
        if data and data.find(strSessionKey) >= 0:

            # Add code to parse the received string and extract the symmetric key //test
            splitd = data.split(" ")
            encr_symm_key = int(splitd[2])
            #print("encrypted symm key ",encr_symm_key) //test
            symmKey = RSAdecrypt(encr_symm_key,d,n)# Make appropriate function call to decrypt the symmetric key
            #print(symmKey," symm")
            # The next line generates the round keys for simplified AES
            simplified_AES.keyExp(symmKey)
            challenge = generateNonce()

            while challenge>n:
              challenge = generateNonce()
            print("the challenge is ",challenge) 
            temp = RSAdecrypt(challenge, d, n)
            #print ("RSAed nonce",temp) //test
            msg = SessionKeyResp(temp)
            conn.sendall(bytes(msg,'utf-8'))
            data = conn.recv(1024).decode('utf-8')
            if data and data.find(strNonceResp) >= 0:                # Add code to parse the received string and extract the nonce
                splitd = data.split(" ")
                encryptedChallenge = int(splitd[1])
                #print("plaintext recieved",encryptedChallenge) //test
                # The next line runs AES decryption to retrieve the key.
                decryptedChallenge = simplified_AES.decrypt(encryptedChallenge)
                #print("plaintext decrypted", type(decryptedChallenge)) //test
                msg = nonceVerification(challenge,decryptedChallenge)# Make function call to compare the nonce sent with that received

                conn.sendall(bytes(msg,'utf-8'))
    conn.close()
    

