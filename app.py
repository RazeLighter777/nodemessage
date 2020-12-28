from flask import Flask, request, jsonify
from flask import request
from hashcash import generate_token, solve_token, verify_token, hash
from post import validatePost, forwardPost, generatePostKeys, runPostInterface
import configparser
import click
import json
config = configparser.ConfigParser()
config.read('config.ini')
app = Flask(__name__)
secret_key = generate_token(20)
posts = {} 
cost = int(config['POLICY']['cost'])
@app.route('/demo')
def hashcash_demo():
    token = generate_token(10)
    return str(solve_token(token, cost))
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
def post():
    content = request.get_json(silent=True)
    problem = content['problem']
    soln = content['soln']
    token = content['token']
    sig = content['signature']
    print(content)
    if sig in posts:
        return "exists"
    if verify_token(problem, soln, cost) and hash(secret_key+problem)==token:
        return "good"
    if (not validatePost(content, config['POLICY']['maxLength'], None)):
        return "invalid"
    posts[sig] = content
    forwardPost(content, config['NETWORK']['nodes'].split(","), int(config['POLICY']['forwardCost']))
    return "success"

@app.cli.command()
def genkeys():
    user = generatePostKeys()
    open(config['SERVER']['userFile'], "w").write(json.dumps(user))

@app.cli.command()
def post():
    runPostInterface()
if __name__ == '__main__': 
    app.make_shell_context()
    app.run(host = config['SERVER']['listen'], port = config['SERVER']['port'])
    
