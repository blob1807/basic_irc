package basic_irc_client

import "core:os"
import "core:log"


main :: proc() { 
    context.logger = log.create_console_logger()
    c: Client

    if !get_user_config(&c) {
        os.exit(-1)
    }

    client_runner(&c)
}

