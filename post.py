import rsa
import json
import requests
import traceback
from hashcash import solve_token
from Crypto import Random
from Crypto.Cipher import AES
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
    return True
def forwardPost(content, nodes, maxCost):
    challengesToSolve = {}
    for node in nodes:
        try:
            result = requests.post(node+'/challenge/'+content["signature"], timeout=5)
            if result.headers.get('content-type') == 'application/json':
                challengesToSolve[node] = json.loads(result.content.decode('utf-8'))
        except Exception as e:
            print("Could not challenge node " + node + " exception " + str(e))
            print(traceback.format_exc())
        print(challengesToSolve)
        for challenge in challengesToSolve:
            if int(challengesToSolve[challenge]["cost"]) <= maxCost:
                content.update(solveChallenge(challengesToSolve[challenge]))
                print(content)
                try:
                    r = requests.post(node + '/post', json=content, timeout=5)
                    if (r.content.decode('utf-8') == "success"):
                        print("Post forwarded successfully to " + challenge)
                    else:
                        print("Post not forwarded successfully, error code " + r.content.decode('utf-8'))
                except:
                    print("could not forward to " + challenge)
            else: 
                print("Too lazy to solve challenge! Try upping forwardCost.")

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

def runPostInterface(user, nodes, config):
    post = ""
    signkey = None
    while True:
        post = input("Enter post text <=250 characters: ")
        if config['CLIENT']['encrypted']=="ask":
            while True:
                ans = input("Would you like to encrypt your post? y/n")
                if ans=="y":
                    prefix = input("Enter first couple characters of the post id you want to reply to : ")
                    sig = keySigFromPrefix(prefix)
                    if sig==None:
                        input("You didn't enter a valid signature")
                        continue
                    else:
                        break
                if ans=="n":
                    break

        if validatePostText(post):
            break
    privkey = rsa.PrivateKey.load_pkcs1(bytes.fromhex(user["secretKey"]))
    pubkey = rsa.PublicKey.load_pkcs1(bytes.fromhex(user["publicKey"]))
    content = {
                "message" : post,
                "alias" : user["alias"],
                "key" : pubkey.save_pkcs1().hex(),
                "signature" : rsa.sign(bytes(post + user["alias"], 'utf-8'), privkey, 'SHA-256').hex()
              }
    forwardPost(content, nodes, int(config['POLICY']['forwardCost']))


def validatePostText(post):
    return len(post)<=250

def validateAlias(alias):
    return alias.isalnum() and len(alias)<=25 and len(alias)>=3
        
def keyFromSigPrefix(prefix):
    for post in posts:
        if (post['signature'].startswith(prefix)):
            return post['key']
        return None

    

