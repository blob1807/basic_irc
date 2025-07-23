package basic_irc_client

import "core:os"
import "core:log"


main :: proc() { 
    context.logger = log.create_console_logger()
    c: Client

    if !get_user_config(&c) {
        os.exit(-1)
    }

    c.user = "odin"
    c.nick = "odin"

    c.server.url = "127.0.0.1:69"
    //c.server.url = "127.0.0.1:6697"

    client_runner(&c)
}

