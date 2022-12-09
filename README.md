# secure-messenger

Client is started with ./client.py -usr [USERNAME] -pw [PASSWORD] -ip [IP] -port [PORT], with an optional -reg boolean flag to register a new user. Server is started with ./server.py and requires no input. The RSA key pair for the server is hardcoded and needs to be in the same directory. The alice and bob s and v files are used as secrets

The three preregistered users are:

user: Alice, pass: alicesmalice

user: Bob, pass: bobthebuilder

user: Charlie, pass: charlieparty

Once a client is started, there are four commands: *list*, which lists all signed in users, *connect [USER]*, which initiates a session with a user, *send [USER] [MESSAGE]* which sends a message via an existing connection, and *logout*, which logs out of the account.

The server will backup the directory of users to disk, so the server going down will not remove all non-hardcoded registrations. 
