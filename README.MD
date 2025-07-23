# Basic IRC Client & Server
A basic IRC Client & Server written in Odin as a toy & example project.   
The Client is limited to 1 channel & server connection at a time.  
Whilst the Server in set up to handle multiple channels, has only been tested with one.  
Both will handle & send UTF-8, however the Server's case mapping is always ASCII.  
Each sub-package also has a `main.odin` for easy up and gp.

# Server
The Server only supports the following commands; `INFO`, `JOIN`, `KICK`, `KILL`, `LIST`, `LUSERS` `MOTD`, `NAMES`, `NICK`, `PART`, `PING`, `PONG`, `PRIVMSG`, `TIME`, `USER`, `VERSION`, `WHO`, `WHOIS` & `QUIT`. All others are reponded with a `ERR_UNKNOWNCOMMAND`.  
These were chosen as the mininum number of commands needs to operate an IRC server. 

# Examples

### Server
```odin
package irc_server_example

import irc "basic_irc/server"

main :: proc() {
    s: irc.Server
    irc.init_server(&s, irc.DEFAULT_ADDRESS)
    defer irc.server_cleanup(&s)

    // irc.set_ctrl_hander()
    irc.server_runner(&s)
}
```

### Client
```odin
package irc_client_example

import "core:log"
import "core:os"
import irc "basic_irc/client"

main :: proc() { 
    c: irc.Client

    irc.init_client(&c, "odin", url = "127.0.0.1:6697")
    defer irc.client_cleanup(&c)

    // Optional get use input for config
    /*if !irc.get_user_config(&c) {
        os.exit(-1)
    }*/

    irc.client_runner(&c)
}
```

# WARNING
Neither the Client or Server have been hardend nor use TLS and should NOT be used on untrusted networks.