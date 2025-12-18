package basic_irc_client

import "core:log"


main :: proc() { 
	context.logger = log.create_console_logger()
	c: Client

	init_client(&c, "odin", "127.0.0.1:6667")
	defer client_cleanup(&c)

	/*if !get_user_config(&c) {
		return
	}*/

	client_runner(&c)
}

