import rsa
import json
import requests
import traceback
from flask import current_app

from hashcash import solve_token


def validatePost(post, maxLen, notories):
    #Validate the signature
    pk = rsa.PublicKey.load_pkcs1(bytes.fromhex(post["key"]))
    try: 
        rsa.verify(bytes(post["message"]+ post["alias"], 'utf-8'), bytes.fromhex(post['signature']), pk)
    except:
        print("validation failed")
        return False
    #Validate length requirements.
    if len(post["message"]) > maxLen:
        return False
    #TODO Validate notories
    #validate fields
    for key in post.keys():
        if not (key in ["key", "nonce","tag", "message", "problem", "soln", "token", "encrypted", "signature", "reply", "signkey", "alias"]):
                return False
    return True
def forwardPost(content, nodes, maxCost):
    with current_app.app_context():
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
                    except Exception as e:
                        current_app.logger.info("could not forward to " + challenge)
                        print(str(e))
                        print(traceback.format_exc())
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


def validatePostText(post):
    return len(post)<=250 and len(post)>=8

def validateAlias(alias):
    return alias.isalnum() and len(alias)<=25 and len(alias)>=3
        
def keyStringFromSigPrefix(prefix, posts):
    for post in posts:
        if (posts[post]['signature'].startswith(prefix)):
            return posts[post]['key']
        return None



    

