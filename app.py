from flask import Flask, request, jsonify
from flask import request
from hashcash import generate_token, solve_token, verify_token, hash
from post import validatePost, forwardPost, generatePostKeys, runPostInterface
import configparser
import click
from transform import interpretPost
import json
config = configparser.ConfigParser()
config.read('config.ini')
app = Flask(__name__)
secret_key = generate_token(20)
posts = {} 
cost = int(config['POLICY']['cost'])
forwardCost = int(config['POLICY']['forwardCost'])
nodes = config['NETWORK']['nodes'].split(",")
@app.route('/demo')
def hashcash_demo():
    token = generate_token(10)
    return str(solve_token(token, cost))
@app.route('/read')
def main():
    showPosts()
    return "good"

@app.route('/challenge/<sig>', methods = ['POST'])
def getPostChallenge(sig):
    if (sig in posts):
        return "exists"
    problem = generate_token(20)
    return {
                "problem" : problem,
                "cost" : cost,
                "token" : hash(secret_key + problem)
           }
@app.route('/post',methods = ['POST'])
def remotePost():
    content = request.get_json(silent=True)
    problem = content['problem']
    soln = content['soln']
    token = content['token']
    sig = content['signature']
    print(content)
    if sig in posts:
        return "exists"
    if not verify_token(problem, soln, cost) and hash(secret_key+problem)==token:
        return "token validation failed"
    if (not validatePost(content, int(config['POLICY']['maxLength']), None)):
        return "invalid post"
    posts[sig] = content
    forwardPost(content, nodes, forwardCost)
    return "success"

@app.cli.command()
def genkeys():
    user = generatePostKeys()
    open(config['SERVER']['userFile'], "w").write(json.dumps(user))

@app.cli.command()
def post():
    runPostInterface(json.loads(open(config['SERVER']['userFile'], "r").read()), nodes, forwardCost)

def showPosts():
    print(posts)
if __name__ == '__main__': 
    app.run(host = config['SERVER']['listen'], port = config['SERVER']['port'])
    
