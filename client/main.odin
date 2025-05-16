package basic_irc_client

import "base:runtime"
import ir "base:intrinsics"

import "core:fmt"
import "core:net"
import "core:os"
import "core:thread"
import "core:sync"
import "core:time"
import "core:bytes"
import "core:strings"
import "core:strconv"
import "core:reflect"
import "core:log"
import "core:io"
import "core:unicode/utf8"
import sa "core:container/small_array"



HELP :: `
================================================================================================

    A basic multi-threaded IRC client with simple formating.
    Only 1 channel & server can be connected to at once.

    Usage:
        Any non commands will be sent as a noraml message

        Commands:
            prefix: !

            help (h)
                prints this

            quit (q) / exit (e) [optional]<leave message>
                quits program. leaves current server / channel. sends leave message when given. 

            leave (l) <server (s) / channel (c)> [optional]<leave message>
                leaves current server / channel. sends leave message when given.

            join (j) <server (s) / channel (c)> <url / name> [optional]<leave message>
                joins server / channel. leaving current one. sends leave message when given.

            cmd (c) <command> <parameters>
                send IRC command
            !
                ingore command. sent as normal message.

================================================================================================
`

client_runner :: proc() {
    c: Client
    buf: [64]byte

    /*
    fmt.println(" Required:")
    fmt.print  ("    Username: ")
    n, read_err := os.read(os.stdin, buf[:])
    if read_err != nil {
        fmt.eprintln("ERROR: Failed to read input:", read_err)
        os.exit(-1)
    }
    if n <= 2 {
        fmt.eprintln("ERROR: No Username was given")
        os.exit(-1)
    }
    c.user = strings.clone(strings.trim_right_space(string(buf[:n])))


    fmt.print  ("  Server URL: ")
    n, read_err = os.read(os.stdin, buf[:])
    if read_err != nil {
        fmt.eprintln("ERROR: Failed to read input:", read_err)
        os.exit(-1)
    }
    if n <= 2 {
        fmt.eprintln("ERROR: No Username was given")
        os.exit(-1)
    }
    c.server.url = strings.clone(strings.trim_right_space(string(buf[:n])))


    fmt.println(" Optional:")
    fmt.print  ("    Nickname: ") 
    n, read_err = os.read(os.stdin, buf[:])
    if read_err != nil {
        fmt.eprintln("ERROR: Failed to read input:", read_err)
        os.exit(-1)
    }
    if n > 2 {
        c.nick = strings.clone(strings.trim_right_space(string(buf[:n])))
    } else {
        c.nick = strings.clone(c.user)
    }


    fmt.print  ("     Channel: ") 
    n, read_err = os.read(os.stdin, buf[:])
    if read_err != nil {
        fmt.eprintln("ERROR: Failed to read input:", read_err)
        os.exit(-1)
    }
    if n > 2 {
        c.chan = strings.clone(strings.trim_right_space(string(buf[:n])))
    }


    fmt.print  ("    Password: ") 
    n, read_err = os.read(os.stdin, buf[:])
    if read_err != nil {
        fmt.eprintln("ERROR: Failed to read input:", read_err)
        os.exit(-1)
    }
    if n > 2 {
        c.pass = strings.clone(strings.trim_right_space(string(buf[:n])))
    }
    */

    c.user = "odin"
    c.nick = "odin"

    IP :: "127.0.0.1:69"
    //IP :: "127.0.0.1:6697"

    server_err := join_server(&c, IP)
    if server_err != nil {
        fmt.eprintfln("ERROR: Failed to connect to server %w  %v", IP, server_err)
        os.exit(-1)
    }

    recv_thr := thread.create_and_start_with_poly_data(&c, recv_thread)

    fmt.println(HELP) 
    join_chan(&c, "#main")
    enable_raw_input()

    loop: for {
        buf: [MAX_MESSAGE_SIZE]u8
        
        str, read_err := read_input(&c, buf[:])
        if read_err != nil {
            eprintln(&c, "ERROR: Failed to read input:", read_err)
            os.exit(-1)
        }

        str = strings.trim_right_space(str)

        if len(str) == 0 {
            eprintln(&c, "ERROR: No Message was given.")
            continue
        }

        if str[0] == '!' {
            sync.lock(&c.mutex)
            fmt.println("  cmd:", str)
            sync.unlock(&c.mutex)

            if len(str) == 1 {
                eprintln(&c, "ERROR: No Command was given.")
                continue
            }

            i := strings.index_byte(str, ' ')
            if i == -1 {
                i = len(str)
            }

            switch str[1:i] {
            case "help", "h":
                println(&c, HELP)

            case "quit", "q", "exit", "e":
                mess: string
                if i != len(str) {
                    mess = str[i+1:]
                }

                log.debug("Quiting")
                leave_server(&c, mess)

                sync.atomic_store(&c.close_thread, true)
                sync.barrier_wait(&c.close_barrier)

                break loop

            case "leave", "l":
                if i == len(str) {
                    fmt.eprintln("No paramator was given. <server (s) or channel (c)> needs to be given.")
                    continue
                }

                mess, type: string
                str := str[i+1:]

                i := strings.index_byte(str, ' ')
                if i == -1 {
                    type = str
                
                } else {
                    type = str[:i]
                    mess = str[i+1:]
                }

                switch type {
                case "server", "s":
                    leave_server(&c, mess)

                case "channel", "c":
                    leave_chan(&c, mess)
                }

            case "join", "j":
                if i == len(str) {
                    fmt.eprintln("No paramator was given. <server (s) or channel (c)> & <url / name> need to be given.")
                    continue
                }

                type, dst, mess: string
                str := str[i+1:]

                i := strings.index_byte(str, ' ')
                if i == -1 {
                    fmt.eprintln("No paramator was given. both <server (s) or channel (c)> & <url / name> need to be given.")
                    continue
                
                } else {
                    type = str[:i]
                    str = str[i+1:]

                    i := strings.index_byte(str, ' ')
                    if i == -1 {
                        dst = str

                    } else {
                        dst = str[:i]
                        mess = str[i+1:]
                    }
                }

                switch type {
                case "server", "s":
                    leave_server(&c, mess)

                    sync.atomic_store(&c.pause_thread, true)
                    sync.barrier_wait(&c.pause_barrier)

                    join_server(&c, dst)
                    sync.atomic_store(&c.pause_thread, false)

                case "channel", "c":
                    leave_chan(&c, mess)
                    join_chan(&c, dst)
                }

            case "cmd", "c":
                send_message(&c, str[i+1:])

            case:
                if str[1] == '!' {
                    send_message(&c, str[1:])
                } else {
                    eprintln(&c, "ERROR: Unkown Command:", str[:i])
                }
            }

        } else {
            sync.lock(&c.mutex)
            println(&c, " mess:", str)
            sync.unlock(&c.mutex)

            send_message(&c, str)
        }
    }

    net.close(c.sock)
    thread.destroy(recv_thr)

    return
}


main :: proc() { 
    context.logger = log.create_console_logger()
    client_runner()
}

