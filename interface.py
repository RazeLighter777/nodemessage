import json
import os

import rsa
from Crypto.Cipher import AES

import hashcash
import getpass
from post import validatePostText, forwardPost, validateAlias, keyStringFromSigPrefix
from transform import interpretPost
from user import genPasswordHash, createUserSession, getSecretKey


def tui(user, posts, nodes, config):
    print("Welcome " + user['alias'] + "!")
    userSession = ""
    while True:
        password = input("Enter password : ")
        userSession = createUserSession(user, password, 1000000000000000000000000000000000)
        if userSession != None:
            print("Password Accepted.")
            break
        else:
            print("Password Invalid.")
    pos = []
    while True:
        command = input('$[' + user['alias'] + ']>  ')
        tokens  = command.split(' ')
        if command == "?":
            help()
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
                runPostInterface(user, userSession, nodes, config, posts)
            elif (tokens[0] == 'top'):
                top(posts, user, userSession)
            elif (tokens[0].startswith("@")):
                ps = getPostByPrefix(tokens[0][1:], posts)
                if (ps != None):
                    pos.append(ps["signature"])
            elif (tokens[0] == 'ls'):
                ls(pos, posts, user, userSession)
            elif (tokens[0] == 'back'):
                back(pos)
            elif (tokens[0] == 'top'):
                top(posts, user, userSession)
            else:
                print('Invalid command.')
                help()
        else:
            continue


def back(pos):
    if len(pos) != 0:
        pos.pop()
    else:
        print("Already at top!")


def ls(pos, posts, user, userSession):
    if len(pos) == 0:
        top(posts, user, userSession)
        return
    rootPost = getPostSignatureFromPostPrefix(posts, pos[-1])
    displayPost(posts[rootPost], posts, user, userSession)
    printDivider()
    for post in getReplies(posts, rootPost):
        displayPost(post, posts, user, userSession)


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
        if "reply" not in posts[post]:
            displayPost(posts[post], posts, user, userSession)

def displayPost(post, posts, user, userSession):
    print("( @" + post["signature"][0:10] + " ) [ #" + hashcash.hash(post['key'])[0:10] + ":" + post['alias'] + " ] R:" + str(getNumberOfReplies(posts, post["signature"])) + " > ")
    if post["encrypted"] == "True":
        print("ENCRYPTED : " + str(getEncryptedPostMessage(user, userSession, post)))
    else:
        print(interpretPost(post["message"]))

def decrypt(password, ciphertext, nonce, tag):
    ciph = AES.new(bytes.fromhex(hashcash.hash(password)), AES.MODE_EAX, nonce=bytes.fromhex(nonce))
    try:
        #ciph.verify(bytes.fromhex(tag))
        plaintext = ciph.decrypt(bytes.fromhex(ciphertext))
        return plaintext
    except:
        return None
def getEncryptedPostMessage(user, userSession, post):
    mnonce = bytes.fromhex(post["nonce"])
    tag = bytes.fromhex(post["tag"])
    #TODO Replace this secret key with the right one
    secretKey = userSession["decryptedSecretKey"]
    cipher = None
    try:
        cipher = AES.new(rsa.decrypt(bytearray.fromhex(post["signkey"]), secretKey), AES.MODE_EAX, nonce = mnonce)
    #except:
    #    return "This post has a malformed signing key. "
    #try:
    #    cipher.verify(tag)
    except:
        return "This message has jacked up AES encryption."
    return cipher.decrypt(bytearray.fromhex(post["message"])).decode('utf-8')


def getPostSignatureFromPostPrefix(posts, prefix):
    for post in posts:
        if post.startswith(prefix):
            return post

def runPostInterface(user, userSession, nodes, config, posts):
    post = ""
    signkey = None
    reply = None
    blowkey = None
    tag = None
    while True:
        post = input("Enter post text <=250 characters: ")
        if config['CLIENT']['encrypted']=="ask":
            while True:
                ans = input("Would you like to encrypt your post? y/n : ")
                if ans=="y":
                    while True:
                        prefix = input("Enter first couple characters of the post id (@) or the key id ($) you want to reply to : ")
                        if prefix.startswith("@"):
                            reply = "@" + getPostSignatureFromPostPrefix(posts, prefix[1:])
                        elif prefix.startswith("$"):
                            #TODO Add private keys
                            pass
                        elif prefix.startswith("#"):
                            #TODO Add user keys
                            pass
                        if reply != None:
                            break

                    blowkey = os.urandom(32)
                    signkey = rsa.encrypt(blowkey,rsa.PublicKey.load_pkcs1(bytes.fromhex(keyStringFromSigPrefix(prefix[1:], posts))))
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
        content["nonce"] = nonce.hex()
        content["tag"] = tag.hex()
        content['message'] = message.hex()
    content["signature"] = rsa.sign((str(content['message']) + user["alias"]).encode('utf-8'), privkey, 'SHA-256').hex()
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
            cipher = AES.new(bytes.fromhex(hashcash.hash(blowkey)), AES.MODE_EAX)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(privkey.save_pkcs1().hex().encode('utf-8'))
            break

    userkeys = {}
    return { "keypairs": {}, "nonce" : nonce.hex(), "tag" : tag.hex(), "userkeys" : userkeys, "passwordHash" : password, "alias" : alias, "secretKey" : ciphertext.hex(), "publicKey" : pubkey.save_pkcs1().hex()}

def getPostByPrefix(prefix, posts):
    for post in posts:
        if posts[post]["signature"].startswith(prefix):
            return posts[post]
def getReplies(posts, query):
    replies = []
    for post in posts:
        if "reply" in posts[post]:
            if (posts[post]["reply"])[1:].startswith(query):
                replies.append( posts[post])
    return replies
def getNumberOfReplies(posts, query):
    count = 0
    for post in posts:
        if "reply" in posts[post]:
            if posts[post]["reply"].startswith("@") and posts[post]["reply"][1:].startswith(query):
                count = count + 1
    return count
#def displayPost(post, posts, user):
#    print("( @" + post["signature"][0:10] + " )"+ "R:" + str(getNumberOfReplies(posts, post["signature"]))+  " [ #" + hashcash.hash(post['key'])[0:10] + ":" + post['alias'] + " ] " )
def top(posts, user, userSession):
    for post in posts:
        if "reply" not in posts[post]:
            displayPost(posts[post], posts, user, userSession)
            printDivider()

def printDivider():
    print("---------------------------------")


def addKeyPair(user):
    try:
        ksi = json.loads(input("Paste your keystring here. Note that anyone else who also has this keystring will be able to read messages made with this key : "))
    except:
        print("Invalid keystring.")
        return
    user['keypairs'] = user['keypairs'] + ksi