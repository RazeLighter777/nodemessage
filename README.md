# Ideas
- P2P over REST, implementation in python. 
- All users endlessly forward signed messages to eachother.
- Runs entirely in memory to prevent glowies from logging.
- Messages are dropped if they :

A : Have been seen before. 

B : Are unauthorized. (custom settings)

C : Do not meet the hashcash requirement. 

- Messages expire after a certain amount of time set by the user.
- Two modes NAT and unNAT mode.

A : NAT mode is for most end users. Requires two minimum unNAT nodes

B : unNAT mode is for server hosters. Endlessly forwards messages.

- Procedures to send messages:

A : Node 1 wants to share a message with node 2. 

B : Node 1 makes a HAS request containing the message hash. Node 2 returns a YES or NO response 
with a hashcash challenge. 

C : If node 1 recieves yes, it forwards the message to node 2 with the solved hashcash challenge. 

D : After a certain amount of time, the message is deleted from node 2. 

- Accounts may be signed with keys that are  also be signed by an authority. Some servers can only accept authorized messages to prevent spam.

- Basically, all of the servers are spamming HAS requests at eachother. However, the rate at which the requests are forwarded is limited by the hashcash system. 

# Internals
Post fields:

- message : the message contained within the post. 

- alias : the user's nickname.

- key : the users public key. 

- signature : the signature of the message.

- (optional) notories : optional signatures and public keys of other users that signed this message. 


Post methods: 

- (optional) hashcash : the normal way to forward a post. Costs a sizeable amount of computing power. Default behavior is to use this method to forward messages if vouchers run out. 

- (optional) voucher : a reward given by one node to another nodefor forwarding posts -- or for any other reason. Usually when a forwarded post is found on a third node. Works only for the server that forwarded it. Allows cheap creation of posts. Each voucher can only be used once. 

Voucher:

- Token : The voucher token code. Can only be used once. Allows forwarding posts without hashcash. 

- Hostname : The hostname of the voucher authority.


curl  -H 'Content-Type: application/json' --data '{"problem":"D343791A3C","soln":"01"}' -X POST 192.168.1.195:5000/post 
