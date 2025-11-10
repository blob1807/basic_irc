#+build windows
package basic_irc_client

import "base:runtime"

import "core:fmt"
import win "core:sys/windows"

@(private="file")
default_cp: win.CODEPAGE


@(private)
ctrl_handler :: proc "system" (dwCtrlType: win.DWORD) -> win.BOOL {
    if dwCtrlType == win.CTRL_C_EVENT {
        context = runtime.default_context()
        fini()
    }
    return false
}


@(init)
init :: proc "contextless" () {
    context = runtime.default_context()
    default_cp = win.GetConsoleOutputCP()

    if win.SetConsoleCtrlHandler(ctrl_handler, true) == win.FALSE {
        err := win.GetLastError()
        fmt.printf("Unable to set console output\nError: %v (%v)", win.System_Error(err), err)
    }

    if win.SetConsoleOutputCP(.UTF8) == win.FALSE {
        err := win.GetLastError()
        fmt.printf("Unable to set console output to UTF8.\nError: %v (%v)", win.System_Error(err), err)
    }

    // Taken from: https://github.com/tartley/colorama/blob/master/colorama/winterm.py#L178
    // "If you're on a recent version of Windows 10 or better, and your stdout/stderr are pointing to a Windows console, "
    // "then this will flip the magic configuration switch to enable Windows' built-in ANSI support."
    handle := win.GetStdHandle(win.STD_OUTPUT_HANDLE)
    mode: win.DWORD
    if win.GetConsoleMode(handle, &mode) == win.FALSE {
        err := win.GetLastError()
        fmt.eprintln("Failed to get console mode.\nError: %v (%v)", win.System_Error(err), err)
        return
    }
    if win.SetConsoleMode(handle, mode | win.ENABLE_VIRTUAL_TERMINAL_PROCESSING | win.ENABLE_PROCESSED_OUTPUT) == win.FALSE {
        err := win.GetLastError()
        fmt.eprintln("Failed to set console mode.\nError: %v (%v)", win.System_Error(err), err)
        return
    }
    if win.GetConsoleMode(handle, &mode) == win.FALSE {
        err := win.GetLastError()
        fmt.eprintln("Failed to get console mode.\nError: %v (%v)", win.System_Error(err), err)
        return
    }
    if mode & (win.ENABLE_VIRTUAL_TERMINAL_PROCESSING | win.ENABLE_PROCESSED_OUTPUT) == 0 {
        fmt.eprintln("Console mode ENABLE_VIRTUAL_TERMINAL_PROCESSING was not set.")
        return
    }
}

@(fini)
fini :: proc "contextless" () {
    context = runtime.default_context()
    if win.SetConsoleOutputCP(default_cp) == win.FALSE {
        err := win.GetLastError()
        fmt.eprintfln("Unable to reset console output\nError: %v (%v)", win.System_Error(err), err)
    }

    handle := win.GetStdHandle(win.STD_OUTPUT_HANDLE)
    mode: win.DWORD
    if !win.GetConsoleMode(handle, &mode) {
        err := win.GetLastError()
        fmt.eprintfln("Unable to get console mode\nError: %v (%v)", win.System_Error(err), err)
    }
    if !win.SetConsoleMode(handle, mode &~ (win.ENABLE_VIRTUAL_TERMINAL_PROCESSING | win.ENABLE_PROCESSED_OUTPUT)) {
        err := win.GetLastError()
        fmt.eprintfln("Unable to reset console mode\nError: %v (%v)", win.System_Error(err), err)
    }

    handle = win.GetStdHandle(win.STD_INPUT_HANDLE)
    if !win.GetConsoleMode(handle, &mode) {
        err := win.GetLastError()
        fmt.eprintfln("Unable to get console mode\nError: %v (%v)", win.System_Error(err), err)
    }
    if win.SetConsoleMode(handle, mode | win.ENABLE_ECHO_INPUT | win.ENABLE_LINE_INPUT) == win.FALSE {
        err := win.GetLastError()
        fmt.eprintln("Failed to set console mode.\nError: %v (%v)", win.System_Error(err), err)
        return
    }
}


_enable_raw_input :: proc() {
    handle := win.GetStdHandle(win.STD_INPUT_HANDLE)
    mode: win.DWORD
    if win.GetConsoleMode(handle, &mode) == win.FALSE {
        err := win.GetLastError()
        fmt.eprintln("Failed to get console in mode.\nError: %v (%v)", win.System_Error(err), err)
        return
    }
    if win.SetConsoleMode(handle, mode &~ (win.ENABLE_ECHO_INPUT | win.ENABLE_LINE_INPUT)) == win.FALSE {
        err := win.GetLastError()
        fmt.eprintln("Failed to set console in mode.\nError: %v (%v)", win.System_Error(err), err)
        return
    }
    if win.GetConsoleMode(handle, &mode) == win.FALSE {
        err := win.GetLastError()
        fmt.eprintln("Failed to get console in mode.\nError: %v (%v)", win.System_Error(err), err)
        return
    }
    if mode & (win.ENABLE_ECHO_INPUT | win.ENABLE_LINE_INPUT) != 0 {
        fmt.eprintln("\"Raw\" Console mode was not set.")
    }
}

_disable_raw_input :: proc() {
    handle := win.GetStdHandle(win.STD_INPUT_HANDLE)
    mode: win.DWORD
    if !win.GetConsoleMode(handle, &mode) {
        err := win.GetLastError()
        fmt.eprintfln("Unable to get console mode\nError: %v (%v)", win.System_Error(err), err)
    }
    if win.SetConsoleMode(handle, mode | win.ENABLE_ECHO_INPUT | win.ENABLE_LINE_INPUT) == win.FALSE {
        err := win.GetLastError()
        fmt.eprintln("Failed to set console mode.\nError: %v (%v)", win.System_Error(err), err)
    }
}

