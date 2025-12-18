#+private
#+build windows
package basic_irc_server

import "base:runtime"

import "core:os"
import "core:fmt"
import "core:thread"
import win "core:sys/windows"


@(private)
ctrl_handler :: proc "system" (dwCtrlType: win.DWORD) -> win.BOOL {
    if dwCtrlType == win.CTRL_C_EVENT {
        context = runtime.default_context()
        os.write_string(os.stdout, "Are you sure you'd like to quit? [Y/n] \n")
        buf: [4]u8

        for {
            n, err := os.read(os.stdin, buf[:])
            if err != nil {
                fmt.println("Failed to get input because of:", err)
                os.exit(-1)
            }
            if n == 0 {
                panic("1")
            }
            switch buf[0] {
            case 'y', 'Y', '\r':
                return false
            case 'n', 'N':
                return true
            }
        }
    }
    return false
}


_set_ctrl_hander :: proc() -> (ok: bool) {
    if win.SetConsoleCtrlHandler(ctrl_handler, true) == win.FALSE {
        err := win.GetLastError()
        fmt.printf("Unable to set console output\nError: %v (%v)", win.System_Error(err), err)
        return false
    }
    return true
}


set_thead_name :: proc(name: string, t: ^thread.Thread) {
    str := win.utf8_to_wstring(name)
    win.SetThreadDescription(t.win32_thread, str)
}