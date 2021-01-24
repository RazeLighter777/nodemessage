import hashlib, random, itertools

def hash(s):
    sha1 = hashlib.sha256()
    sha1.update(s.encode())
    return sha1.hexdigest()

def verify_token(problem, soln, length):
    return hash(problem + soln).endswith("0" * length)

def solve_token(problem, length):
    i = 0
    while True:
        i+=1
        for soln in map(''.join, itertools.product('0123456789ABCDEF', repeat=i)):
            if verify_token(problem, soln, length):
                return soln
def generate_token(size):
    r = ""
    for i in range(size):
        r+=random.choice('0123456789ABCDEF')
    return r
