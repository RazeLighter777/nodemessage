from flask import Flask, request, jsonify
from flask import request
from Crypto.PublicKey import RSA
from hashcash import generate_token, solve_token, verify_token, hash
from post import validatePost, forwardPost
import configparser
config = configparser.ConfigParser()
config.read('config.ini')
app = Flask(__name__)
key = RSA.generate(2048)
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
    forwardPost(content, config['NETWORK']['nodes'].split(","))
    return "success"


if __name__ == '__main__': 
    app.run(host = config['SERVER']['listen'], port = config['SERVER']['port'])
