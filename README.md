# secure-messenger

## Running the client
Client is started with ./client.py [-usr USERNAME] [-pw PASSWORD] [-ip IP] [-port PORT] [-reg], where
-reg is an optional boolean flag to register a new user. Server is started with ./server.py and requires 
no input. The RSA key pair for the server is hardcoded and needs to be in the same directory. 
The "&lt;usr>s.txt" and "&lt;usr>v.txt" files for Alice, Bob, Charlie, and Dave as well as "users.txt" are
needed but can be ignored.

## Users
The four preregistered users are:

user: Alice, pass: alicesmalice

user: Bob, pass: bobthebuilder

user: Charlie, pass: charlieparty

user: Dave, pass: davesden

## Commands
Once a client is started, there are four commands: *list*, which lists all signed-in users, 
*connect [USER]*, which initiates a session with a user, *send [USER] [MESSAGE]* which sends 
a message via an existing connection, and *logout*, which logs out of the account.

## Server info
The server will back up the directory of users to disk, so the server going down will not remove 
all non-hardcoded registrations. We recommend that the server not be remotely accessible over SSH,
FTP or the like for security reasons.
