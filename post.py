import rsa
import json
import requests
import traceback
import blowfish
from flask import Flask, current_app
import os
from hashcash import solve_token
from Crypto import Random
def validatePost(post, maxLen, notories):
    #Validate the signature
    pk = rsa.PublicKey.load_pkcs1(bytes.fromhex(post["key"]))
    try: 
        rsa.verify(bytes(post["message"]+post["alias"], 'utf-8'), bytes.fromhex(post['signature']), pk)
    except:
        print("validation failed")
        return False
    #Validate length requirements.
    if len(post["message"]) > maxLen:
        return False
    #TODO Validate notories
    #validate fields
    for key in post.keys():
        if not (key in ["key", "message", "problem", "soln", "token", "encrypted", "signature", "reply", "signkey", "alias"]):
                return False
    return True
def forwardPost(content, nodes, maxCost):
    challengesToSolve = {}
    for node in nodes:
        try:
            result = requests.post(node+'/challenge/'+content["signature"], timeout=5)
            if result.headers.get('content-type') == 'application/json':
                challengesToSolve[node] = json.loads(result.content.decode('utf-8'))
        except Exception as e:
            current_app.logger.info("Could not challenge node " + node + " exception " + str(e))
            current_app.logger.info(traceback.format_exc())
        for challenge in challengesToSolve:
            if int(challengesToSolve[challenge]["cost"]) <= maxCost:
                content.update(solveChallenge(challengesToSolve[challenge]))
                try:
                    r = requests.post(node + '/post', json=content, timeout=5)
                    if (r.content.decode('utf-8') == "success"):
                        print("Post forwarded successfully to " + challenge)
                    else:
                        current_app.logger.info("Post not forwarded successfully, error code " + r.content.decode('utf-8'))
                except:
                    current_app.logger.info("could not forward to " + challenge)
            else: 
                current_app.logger.info("Too lazy to solve challenge! Try upping forwardCost.")

def solveChallenge(challenge):
    cost = int(challenge["cost"])
    problem = challenge["problem"]
    token = challenge["token"]
    return { 
                "problem" : problem,
                "soln" : solve_token(problem, cost),
                "token" : token
           }
def generatePostKeys():
    print("Generating keys for a new user. This will overwrite any existing user.")
    # Loop until the user makes a valid name
    alias = ""
    while True:
        alias = input('Enter a valid alphanumeric alias less than 25 characters. Other people can use this same alias so it doesn\'t have to be unique: ')
        if validateAlias(alias):
            break
    #generate a key
    print("Generating key . . .")
    (pubkey, privkey) = rsa.newkeys(2048)
    print("Key fingerprint : " + pubkey.save_pkcs1().hex())
    print("Key generated.")
    return { "alias" : alias, "secretKey" : privkey.save_pkcs1().hex(), "publicKey" : pubkey.save_pkcs1().hex()}

def addKeyPair(user):
    try:
        ksi = json.loads(input("Paste your keystring here. Note that anyone else who also has this keystring will be able to read messages made with this key : "))
    except:
        print("Invalid keystring.")
    user['keypairs'] = user['keypairs'] + ksi
def runPostInterface(user, nodes, config):
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
                    blowkey = os.urandom(52)
                    signkey = rsa.encrypt(blowkey,rsa.PublicKey.load_pkcs1(bytes.fromhex(user["publicKey"])))    
                    break
                if ans=="n":
                    break

        if validatePostText(post):
            print("Your post does not meet the formatting requirements.")
            break
        
    privkey = rsa.PrivateKey.load_pkcs1(bytes.fromhex(user["secretKey"]))
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
        ciph = blowfish.Cipher(blowkey)
        content['message'] = b"".join(ciph.encrypt_ecb_cts(content['message'].encode())).hex()
    content["signature"] = rsa.sign(bytes(content['message'] + user["alias"], 'utf-8'), privkey, 'SHA-256').hex()
    forwardPost(content, nodes, int(config['POLICY']['forwardCost']))


def validatePostText(post):
    return len(post)<=250 and len(post)>=8

def validateAlias(alias):
    return alias.isalnum() and len(alias)<=25 and len(alias)>=3
        
def keyFromSigPrefix(prefix):
    for post in posts:
        if (post['signature'].startswith(prefix)):
            return post['key']
        return None

    

