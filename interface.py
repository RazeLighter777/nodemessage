import os

import blowfish
import rsa
from Crypto.Cipher import AES

import hashcash
from post import validatePostText, forwardPost, validateAlias
from transform import interpretPost
from user import genPasswordHash, createUserSession, getSecretKey


def tui(user, posts, nodes, config):
    print("Welcome " + user['alias'] + "!")
    userSession = ""
    while True:
        password = input("Enter your password : ")
        userSession = createUserSession(user, password, 1000000000000000000000000000000000)
        if userSession != None:
            print("Password Accepted.")
            break
        else:
            print("Password Invalid")
    while True:
        command = input('$[' + user['alias'] + ']>  ')
        tokens  = command.split(' ')
        if len(tokens) > 0:
            if (tokens[0] == 'alias'):
                print('Your current alias is ' + user['alias'])
            elif command == "?":
                help()
            elif (tokens[0] == 'pubkey'):
                print('Your public RSA-2048 bit key is ' + user['publicKey'])
            elif (tokens[0] == 'nodes'):
                print(nodes)
            elif (tokens[0] == 'post'):
                runPostInterface(user, userSession, nodes, config)
            elif (tokens[0] == 'top'):
                top(posts, user, userSession)
            else:
                print('Invalid command.')
                help()
        else:
            continue

def help():
    print("Valid commands : ")
    print("pubkey : print public key of current user")
    print("alias <name>: print alias or change alias if specified")
    print("post : create post:")
    print("next : view next thread alphabetically")
    print("prev : view previous thread")
    print("search <text>: find a particular thread")
    print("nodes : list currently active nodes")
    print("top : print all top level posts")
    print("? : display this help")
def top(posts, user, userSession):
    for post in posts:
        if not "reply" in posts[post]:
            displayPost(posts[post], user, userSession)

def displayPost(post, user, userSession, password):
    print("( " + post["signature"][0:10] + " ) [ " + post['key'][0:10] + ":" + post['alias'] + " ] " )
    if post["encrypted"] == "True":
        print("ENCRYPTED : " + decrypt(password, post["message"], post["nonce"], post["tag"]))
    else:
        print(interpretPost(post["message"]))

def decrypt(password, ciphertext, nonce, tag):
    ciph = AES.new(bytes.fromhex(hashcash.hash(password)), AES.MODE_EAX, nonce=nonce)
    try:
        ciph.verify(tag)
        plaintext = ciph.decrypt(ciphertext)
        return plaintext
    except:
        return None
def getEncryptedPostMessage(user, userSession, post, decryptedSecretKey):
    nonce = post["nonce"]
    tag = post["tag"]
    secretKey = rsa.PublicKey.load_pkcs1(bytes.fromhex(userSession["decryptedSecretKey"]))
    cipher = AES.new(bytes.fromhex(rsa.decrypt(bytes.fromhex(post["signkey"])),secretKey), AES.MODE_EAX)

def runPostInterface(user, userSession, nodes, config):
    post = ""
    signkey = None
    reply = None
    blowkey = None
    while True:
        post = input("Enter post text <=250 characters: ")
        if config['CLIENT']['encrypted']=="ask":
            while True:
                ans = input("Would you like to encrypt your post? y/n : ")
                if ans=="y":
                    prefix = input("Enter first couple characters of the user id or the key id you want to reply to : ")
                    reply = ""
                    blowkey = os.urandom(32)
                    signkey = rsa.encrypt(blowkey,rsa.PublicKey.load_pkcs1(bytes.fromhex(user["publicKey"])))
                    break
                if ans=="n":
                    break

        if not validatePostText(post):
            print("Your post does not meet the formatting requirements.")
            continue
        else:
            break

    privkey = getSecretKey(userSession)
    pubkey = rsa.PublicKey.load_pkcs1(bytes.fromhex(user["publicKey"]))
    content = {
                "message" : post,
                "alias" : user["alias"],
                "encrypted" : "False",
                "key" : pubkey.save_pkcs1().hex(),
              }
    if blowkey != None:
        content['reply'] = reply
        content['encrypted'] = "True"
        content['signkey'] = signkey.hex()
        ciph = AES.new(blowkey, AES.MODE_EAX)
        nonce = ciph.nonce
        message, tag = ciph.encrypt_and_digest(post.encode('utf-8'))
        content["nonce"] = nonce
        content["tag"] = tag
        content['message'] = message
    content["signature"] = rsa.sign((content['message'].hex() + user["alias"]).encode('utf-8'), privkey, 'SHA-256').hex()
    forwardPost(content, nodes, int(config['POLICY']['forwardCost']))


def generatePostKeys():
    print("Generating keys for a new user. This will overwrite any existing user.")
    # Loop until the user makes a valid name
    alias = ""
    blowkey = ""
    password = ""
    nonce = ""
    tag = ""
    ciphertext = ""
    while True:
        alias = input('Enter a valid alphanumeric alias less than 25 characters. Other people can use this same alias so it doesn\'t have to be unique: ')
        if validateAlias(alias):
            break
    #generate a key
    print("Generating key . . .")
    (pubkey, privkey) = rsa.newkeys(2048)
    print("Key fingerprint : " + hashcash.hash(pubkey.save_pkcs1().hex()))
    print("Key generated.")
    while True:
        password = input("Enter your password for your private key. Keep this password secret! Max length 56 chars. : ")
        blowkey = password
        password = genPasswordHash(password)
        if (len(blowkey)<=56):
            print(hashcash.hash(blowkey))
            cipher = AES.new(bytes.fromhex(hashcash.hash(blowkey)), AES.MODE_EAX)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(privkey.save_pkcs1().hex().encode('utf-8'))
            break

    userkeys = {}

    return { "nonce" : nonce.hex(), "tag" : tag.hex(), "userkeys" : userkeys, "passwordHash" : password, "alias" : alias, "secretKey" : ciphertext.hex(), "publicKey" : pubkey.save_pkcs1().hex()}