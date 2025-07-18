# Basic IRC Client & Server
A basic IRC Client & Server written in Odin as a toy & example project.   
The Client is limited to 1 channel & server connection at a time.  
Whilst the Server in set up to handle multiple channels, has only been tested with one.  
Both will handle & send UTF-8, however the Server's case mapping is always ASCII.

# Server
The Server only supports the following commands; `INFO`, `JOIN`, `KICK`, `KILL`, `LIST`, `LUSERS` `MOTD`, `NAMES`, `NICK`, `PART`, `PING`, `PONG`, `PRIVMSG`, `TIME`, `USER`, `VERSION`, `WHO`, `WHOIS` & `QUIT`. All others are reponded with a `ERR_UNKNOWNCOMMAND`.  
These were chosen as the mininum number of commands needs to operate an IRC server. 

# WARNING
Neither the Client or Server have been hardend nor use TLS and should NOT be used on untrusted networks.