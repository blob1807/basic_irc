package basic_irc_client

import "core:os"
import "core:log"


main :: proc() { 
    context.logger = log.create_console_logger()
    c: Client

    init_client(&c, "odin", "127.0.0.1:6667")
    defer client_cleanup(&c)

    /*if !get_user_config(&c) {
        os.exit(-1)
    }*/

    client_runner(&c)
}

