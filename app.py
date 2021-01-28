from flask import Flask, request, jsonify
from flask import request
import time
from hashcash import generate_token, solve_token, verify_token, hash
from interface import tui, runPostInterface, generatePostKeys
from post import validatePost, forwardPost
import configparser
import click
from transform import interpretPost
import json
from apscheduler.schedulers.background import BackgroundScheduler
import asyncio
from flask.cli import with_appcontext
import threading
import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
config = configparser.ConfigParser()
config.read('config.ini')
app = Flask(__name__)
scheduler = BackgroundScheduler()

loop = asyncio.get_event_loop()

secret_key = generate_token(20)
posts = {} 
cost = int(config['POLICY']['cost'])
forwardCost = int(config['POLICY']['forwardCost'])
nodes = config['NETWORK']['nodes'].split(",")

@app.route('/posts')
def post():
    return posts
@app.route('/read')
def pretty():
    text = "<h>Messages</h>\n"
    for post in posts:
        text += "<p>\n"
        text += "POST ID : " + posts[post]["signature"][0:10] + "<br>"
        text += "USER ID : " + posts[post]["key"][0:10] + "<br>"
        text += "ALIAS : " + posts[post]["alias"] + "<br>"
        text += "MESSAGE : " + posts[post]["message"] +"<br>"
        text += "</p>"
        text += "<br><br>"
    return text

@app.route('/challenge/<sig>', methods = ['POST'])
def getPostChallenge(sig):
    if (sig in posts):
        return "exists"
    problem = generate_token(20)
    return {
                "problem" : problem,
                "cost" : cost,
                "token" : hash(secret_key +  sig + problem)
           }
@app.route('/post',methods = ['POST'])
def remotePost():
    content = request.get_json(silent=True)
    problem = content['problem']
    soln = content['soln']
    token = content['token']
    sig = content['signature']
    if sig in posts:
        return "exists"
    if not verify_token(problem, soln, cost) and hash(secret_key+sig+problem)==token:
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

@click.command()
@with_appcontext
def post():
    runPostInterface(json.loads(open(config['SERVER']['userFile'], "r").read()), nodes, config)
app.cli.add_command(post)
def forward():
    with app.app_context():
        for post in posts:
            forwardPost(posts[post], nodes, forwardCost)
def interface():
    print("Welcome to nodemessage! Your node is up and running.")
    tui(json.loads(open(config['SERVER']['userFile'], "r").read()),posts, nodes, config)
@app.cli.command()
def showPosts():
    print(posts)
def runApp():
    app.run(host = config['SERVER']['listen'], port = config['SERVER']['port'])
if __name__=='__main__':
    scheduler.add_job(forward, 'interval', seconds=int(config['POLICY']['forwardInterval']))
    scheduler.start()
    thread = threading.Thread(target = runApp)
    thread.start()
    time.sleep(1)
    with app.app_context():
        interface()
