import ecdsa
import requests
from hashcash import solve_token
import configparser
def test():
    # SECP256k1 is the Bitcoin elliptic curve
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    hexstr = sk.to_string().hex()
    sk2 = ecdsa.SigningKey.from_string(bytes.fromhex(hexstr), curve=ecdsa.SECP256k1)
    sig = sk.sign(b"message")
    return sk2.get_verifying_key().verify(sig, b"message") # True

print(str(test()))
def validatePost(post, maxLen, notories):
    #Validate the signature
    vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(post["key"], curve=ecdsa.SECP256k1))
    try:
        vk.verify(post["signature"], post["message"]+post["alias"])
    except:
        return False
    #Validate length requirements.
    if len(post["message"] > maxLen):
        return False
    #TODO Validate notories
    return True
def forwardPost(content, nodes, maxCost):
    challengesToSolve = {}
    for node in nodes:
        result = requests.post(node+'/challenge/'+content["signature"])
        if result.content != "exists":
            challengesToSolve[content["signature"]] = result.content
    for challenge in challengesToSolve:
        if int(challenge["cost"]) <= maxCost:
            r = requests.post(node, json=content.update(solveChallenge(challenge)))
            if (r.status_code == 200):
                print("Post forwarded successfully")
            else:
                print("Post not forwarded successfully, error code " + str(r.status_code))
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
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    print("Key fingerprint : " + sk.get_verifying_key().to_string().hex())
    print("Key generated.")
    return { "alias" : alias, "secretKey" : sk.to_string().hex() }

def validateAlias(alias):
    return alias.isalnum() and len(alias)<=25 and len(alias)>=3
        



    

