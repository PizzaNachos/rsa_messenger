## Rsa Messenger
This is a toy project exploring RSA encryption from scratch as well as networking protocals and messengers

the server folder contains a cargo project to run the server which works in the following way
* the server listens for connections
* when the server gets a client connected the client must present its RSA public key as identification
* the server uses the public key to verify the client holds the private key 
* the server then lets other clients send this client messages based on their public key as identification

the client folder contians a cargo project to run the client
* it has 4 modes when you run it, before you can send messages you need a key, run the gen command to generate a key (there are keys generated inside the client directory for your convience, named 1 and 2)
* run in real mode to use your just created key as identification and connect to the server
* create another key and run another client with recievers as each other
* send encrypted messages :)