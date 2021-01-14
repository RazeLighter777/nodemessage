import post
from transform import interpretPost
def tui(user, posts, nodes, config):
    print("Welcome " + user['alias'] + "!")
    while True:
        command = input('$[' + user['alias'] + ']>  ')
        tokens  = command.split(' ')
        if command == "?":
            help()
        if len(tokens) > 0:
            if (tokens[0] == 'alias'):
                print('Your current alias is ' + user['alias'])
            elif (tokens[0] == 'pubkey'):
                print('Your public RSA-2048 bit key is ' + user['publicKey'])
            elif (tokens[0] == 'nodes'):
                print(nodes)
            elif (tokens[0] == 'post'):
                post.runPostInterface(user, nodes, config)
            elif (tokens[0] == 'top'):
                top(posts, user)
            else: 
                print('Invalid command.')
                help()
        else:
            continue

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
def top(posts, user):
    for post in posts:
        if not "reply" in posts[post]:
            displayPost(posts[post], user)

def displayPost(post, user):
    print("( " + post["signature"][0:10] + " ) [ " + post['key'][0:10] + ":" + post['alias'] + " ] " )
    if post["encrypted"] == "True":
        print("ENCRYPTED : " + post["message"])
    else:
        print(interpretPost(post["message"]))

