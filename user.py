import os
from calendar import calendar
from datetime import time

import blowfish
from Crypto.Protocol.KDF import scrypt
import rsa
from Crypto.Cipher import AES

import hashcash


def genPasswordHash(password):
    salt = hashcash.hash(str(os.urandom(52)))
    key = scrypt(password, salt, 32, N=2**14, r=8, p=1).hex()
    return f"{salt}:{key}"

def createUserSession(user, password, expireTime):
    userSession =  {"user" : user, "expireTime" : expireTime}
    userSession["password"] = password
    userSession["decryptedSecretKey"] = getSecretKey(userSession)
    if userSession["decryptedSecretKey"] == None:
        return None
    return userSession

def verifyPassword(password, passwordHash):
    tokens = passwordHash.split(":")
    if tokens[1]==scrypt(password, tokens[0],32, N=2**14, r=8,p=1).hex():
        return True
    return False


def getSecretKey(userSession):
    encKey =userSession["user"]["secretKey"]
    passwordHash = userSession["user"]["passwordHash"]
    if verifyPassword(userSession["password"], passwordHash):
        ciph = AES.new(bytes.fromhex(hashcash.hash(userSession["password"])), AES.MODE_EAX, nonce=bytes.fromhex(userSession["user"]["nonce"]))
        plain = ciph.decrypt(bytes.fromhex(userSession["user"]["secretKey"]))
        secretKey = rsa.PrivateKey.load_pkcs1(bytes.fromhex(plain.decode('utf-8')))
        userSession["decryptedSecretKey"] = secretKey
        try:
            ciph.verify(bytes.fromhex(userSession["user"]["tag"]))
        except:
            return None
        return secretKey
    return None
