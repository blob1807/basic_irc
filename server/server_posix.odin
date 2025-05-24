#+build !windows
package basic_irc_client

import "base:runtime"

import "core:c"
import "core:os"
import "core:fmt"
import psx "core:sys/posix"


@(private)
sig_handler :: proc "c" (sig: c.int) {
    context = runtime.default_context()
    os.write_string(os.stdout, "Are you sure you'd like to quit? [Y/n]")
    buf: [4]u8

    for {
        n, err := os.read(os.stdin, buf[:])
        if err != nil {
            fmt.println("Failed to get input because of:", err)
            os.exit(-1)
        }
        if n == 0 {
            os.exit(0)
        }
        switch buf[0] {
        case 'y', 'Y', '\n':
            os.exit(0)
        case 'n', 'N':
            return
        }
    }
}


_set_ctrl_hander :: proc() -> (ok: bool) {
    if psx.signal(psx.SIGINT, sig_handler) == psx.SIG_ERR {
        err := psx.get_errno()
        fmt.printf("Unable to set console output\nError: %v (%v)", err, int(err))
        return false
    }
    if psx.signal(psx.SIGTSTP, sig_handler) == psx.SIG_ERR {
        err := psx.get_errno()
        fmt.printf("Unable to set console output\nError: %v (%v)", err, int(err))
        return false
    }
    return true
}

