import ecdsa
import json
import requests
from hashcash import solve_token
def validatePost(post, maxLen, notories):
    #Validate the signature
    vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(post["key"]), curve=ecdsa.SECP256k1)
    try: 
        vk.verify(bytes.fromhex(post["signature"]), bytes(post["message"]+post["alias"], 'utf-8'))
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
            if result.content != "exists":
                challengesToSolve[node] = json.loads(result.content.decode('utf-8'))
        except Exception as e:
            print("Could not challenge node " + node + " exception " + str(e))
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
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    print("Key fingerprint : " + sk.get_verifying_key().to_string().hex())
    print("Key generated.")
    return { "alias" : alias, "secretKey" : sk.to_string().hex() }

def runPostInterface(user, nodes, maxCost):
    post = ""
    while True:
        post = input("Enter post text <=250 characters: ")
        if validatePostText(post):
            break
    privkey = ecdsa.SigningKey.from_string(bytes.fromhex(user["secretKey"]), curve=ecdsa.SECP256k1)
    content = {
                "message" : post,
                "alias" : user["alias"],
                "key" : privkey.get_verifying_key().to_string().hex(),
                "signature" : privkey.sign(bytes(post + user["alias"], 'utf-8')).hex()
              }
    forwardPost(content, nodes, maxCost)


def validatePostText(post):
    return len(post)<=250
def validateAlias(alias):
    return alias.isalnum() and len(alias)<=25 and len(alias)>=3
        



    

