import ecdsa

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
def forwardPost(content, nodes):
    return

