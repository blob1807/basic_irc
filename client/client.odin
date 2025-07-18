package basic_irc_client 

import "base:runtime"

import "core:os"
import "core:io"
import "core:net"
import "core:log"
import "core:fmt"
import "core:sync"
import "core:time"
import "core:bytes"
import "core:strings"
import "core:strconv"
import "core:reflect"
import "core:unicode/utf8"
import sa "core:container/small_array"

import "../common"


// Zeros the given Client
init_client :: proc(c: ^Client, user: string, nick := "", real := "", pass := "", alloc := context.allocator) {
    runtime.mem_zero(c, size_of(Client))

    c.user = user
    c.nick = nick != "" ? nick : user
    c.real = real != "" ? real : user
    c.pass = pass

    c.parsed = make([dynamic]Message, 0, 5, alloc)

    sync.barrier_init(&c.pause_barrier, 3)
    sync.barrier_init(&c.close_barrier, 3)

}


get_messaage :: proc(c: ^Client, alloc := context.allocator) -> (mess: Message, err: Error) {
    recv_data(c) or_return
    return parse_message(c, alloc = alloc)
}


pop_message :: proc(c: ^Client, pos := -1, loc := #caller_location) -> (ok: bool) {
    if pos+2 >= NET_BUFFER_SIZE && c.net.pos == NET_BUFFER_SIZE {
        return 
    }

    if pos > -1 {
        log.debug(loc)
        c.net.pos = copy(c.net.buf[:], c.net.buf[pos+2:c.net.pos])
        return true
    }

    if i := bytes.index(c.net.buf[:], MESS_END); i != -1 {
        c.net.pos = copy(c.net.buf[:], c.net.buf[i+2:c.net.pos])
        return true
    }
    
    return
}


destroy_message :: proc(mess: Message, free_raw := false, alloc := context.allocator) {
    delete(mess.params)
    if free_raw {
        delete(mess.raw)
    }
}


recv_data :: proc(c: ^Client) -> (err: net.Network_Error) {
    buf: [NET_READ_SIZE]byte
    s,l: int

    for c.net.pos < MAX_MESSAGE_SIZE {
        s, err = net.recv_tcp(c.sock, buf[:])

        if s > 0 {
            c.net.pos += copy(c.net.buf[c.net.pos:], buf[:s])
        }

        if err != nil || bytes.contains(buf[l:s], MESS_END) {
            break
        }

        l = s
    }

    return
}


send_message :: proc(c: ^Client, mess: string) -> (err: Error) {
    if len(mess) > (MAX_MESSAGE_SIZE - len(c.chan) + len("PRIVMSG  :\r\n")) {
        print_str(c, "ERROR: Message is to long.", true)
        return IRC_Errors.Message_To_Big
    }

    return send_command(c.sock, "PRIVMSG ", c.chan, " :", mess, "\r\n")
}


send_command :: proc(sock: net.TCP_Socket, cmd: ..string) -> (err: net.Network_Error) {
    i: int
    buf: [MAX_MESSAGE_SIZE]byte
    for p in cmd { 
        i += copy(buf[i:], p)
    }

    n := net.send_tcp(sock, buf[:i]) or_return
    assert(n == i)

    return
}


join_chan :: proc(c: ^Client, chan: string) -> (err: net.Network_Error) {
    send_command(c.sock, "JOIN ", chan, "\r\n") or_return
    c.chan = chan
    return
}


leave_chan :: proc(c: ^Client, leave_mess := "") -> (err: net.Network_Error) {
    send_command(c.sock, "PART ", c.chan, " ", leave_mess, "\r\n") or_return
    c.chan = ""
    return
}


leave_server :: proc(c: ^Client, leave_mess := "") -> (err: net.Network_Error) {
    leave_chan(c, leave_mess) or_return
    if leave_mess != "" {
        send_command(c.sock, "QUIT ", leave_mess, " \r\n") or_return
    } else {
        send_command(c.sock, "QUIT \r\n") or_return
    }
    
    time.sleep(time.Second)
    return
}


join_server :: proc(c: ^Client, dst: string, alloc := context.allocator) -> (err: Error) {
    context.allocator = alloc

    sock := net.dial_tcp(dst) or_return
    n_err := net.set_option(sock, .Receive_Timeout, NET_TIMEOUT)
    if n_err != nil {
        return net.Network_Error(n_err)
    }

    c.sock = sock
    c.server.url = dst

    log.debug("Dialed server", c.server.url)
    

    mess: Message

    if c.pass != "" {
        send_command(sock, "PASS ", c.pass, "\r\n") or_return
        // TODO: Error from server
    }

    send_command(sock, "NICK ", c.nick, "\r\n") or_return
    log.debug("Sent Nick", c.nick)
    mess, err = get_messaage(c)
    if v, o := err.(net.Network_Error); o {
        if vv, oo := v.(net.TCP_Recv_Error); oo && vv != .Timeout {
            return
        }
    } else if err != nil {
        return
    }

    #partial switch mess.code {
    case .ERR_INPUTTOOLONG, .ERR_NOTREGISTERED, .ERR_UNKNOWNERROR: fallthrough
    case .ERR_NONICKNAMEGIVEN, .ERR_ERRONEUSNICKNAME, .ERR_NICKNAMEINUSE, .ERR_NICKCOLLISION:
        print_mess(c, mess)
        pop_message(c, len(mess.raw))
        destroy_message(mess)
        return .Join_Server_Fail
    }

    send_command(sock, "USER ", c.user, " 0 * :", c.nick, "\r\n") or_return
    log.debug("Sent User", c.user)
    mess, err = get_messaage(c)
    if v, o := err.(net.Network_Error); o {
        if vv, oo := v.(net.TCP_Recv_Error); oo && vv != .Timeout {
            return
        }
    } else if err != nil {
        return
    }
    
    #partial switch mess.code {
    case .ERR_INPUTTOOLONG, .ERR_NOTREGISTERED, .ERR_UNKNOWNERROR: fallthrough
    case .ERR_NEEDMOREPARAMS, .ERR_ALREADYREGISTERED, .ERR_INVALIDUSERNAME: 
        print_mess(c, mess)
        pop_message(c, len(mess.raw))
        destroy_message(mess)
        return .Join_Server_Fail
    }


    loop: for {
        err = recv_data(c)
        if v, ok := err.(net.Network_Error); ok {
            if vv, okv := v.(net.TCP_Recv_Error); okv && vv == .Timeout {
                err = nil
                break loop 
            }
        }
        if err != nil {
            return
        }

        for c.net.pos > 0 {
            mess, err = parse_message(c, true, true)

            if err != nil {
                if _, ok := err.(IRC_Errors); !ok {
                    destroy_message(mess)
                }
                
                if c.net.pos == NET_BUFFER_SIZE {
                    print_str(c, "No Message was found. Printing & Clearing Buffer.", true)
                    println(c, c.net.buf[:])
                    c.net.pos = 0
                }
                break 
            }

            append(&c.parsed, mess)

            if mess.code == .RPL_WELCOME {
                if !common.is_equal(mess.params[0], c.nick) {
                    println(c, "Server has changed nick from", c.nick, "to", mess.params[0])
                    delete(c.nick)
                    c.nick = strings.clone(mess.params[0]) or_return
                }

                if mess.sender.type == .Server {
                    c.server.name = strings.clone(mess.sender.name) or_return
                } else {
                    eprintln(c, "Expected host name. Got:", mess.sender)
                }

            } else if mess.cmd == "PING" {
                if len(mess.params) != 0 {
                    send_command(sock, "PONG", mess.params[0], "\r\n")
                } else {
                    send_command(sock, "PONG \r\n")
                }
                
            }
        }
    }

    log.debug("Connected to Server", c.server.url)
    return
}


parse_message :: proc(c: ^Client, clone_mess := false, pop_mess := false, alloc := context.allocator) -> (mess: Message, err: Error) {
    if i := bytes.index(c.net.buf[:c.net.pos], MESS_END); i != -1 {
        if clone_mess {
            mess.raw = strings.clone(string(c.net.buf[:i]), alloc) or_return
            if pop_mess {
                c.net.pos = copy(c.net.buf[:], c.net.buf[i+2:c.net.pos])
            }

        } else {
            mess.raw = string(c.net.buf[:i]) 
        }
        
    } else {
        err = IRC_Errors.No_End_Of_Message
        return
    }

    mess.recived = time.now()

    i: int
    s := mess.raw

    // Tags Check
    if s[0] == '@' {
        i = strings.index_byte(s, ' ')
        mess.tags = s[1:i]
        s = s[i+1:]
    }

    // Source Check
    if s[0] == ':' {
        i = strings.index_byte(s, ' ')
        sender := s[1:i]
        mess.sender.name = sender
        
        // TODO: Probably slower then what I had but is "more" correct
        ai := strings.index_rune(sender, '!')
        if len(sender) <= ai {
            mess.sender.type = .Invalid

        } else if ai == -1 {
            mess.sender.type = .Server

        } else {
            bi := strings.index_rune(sender[ai:], '@')
            if len(sender[ai:]) <= bi {
                mess.sender.type = .Invalid

            } else if bi == -1 {
                mess.sender.type = .Server

            } else {
                if sender[:ai] == c.nick {
                    mess.sender.type = .Self

                } else {
                    mess.sender.type = .User
                }
            }
        }
        s = s[i+1:]
    }

    // Code or Command check
    i = strings.index_byte(s, ' ')
    if i == -1 {
        print_str(c, "Failed to parse Code or Command", true)

    } else if v, ok := strconv.parse_int(s[:i], 10); ok {
        mess.code = common.Response_Code(v)
        s = s[i+1:]

    } else {
        mess.cmd = s[:i]
        s = s[i+1:]
    }

    i = strings.index(s, " :")

    if i == -1 {
        mess.params = parse_params(s) or_return
    } else {
        mess.params = parse_params(s[:i]) or_return
        mess.tail = s[i+2:]
    }

    return
}


parse_params :: proc(params: string, alloc := context.allocator) -> (res: []string, err: runtime.Allocator_Error) {
    // https://modern.ircdocs.horse/#parameters
    count :: proc(s: string) -> (res: int) {
        res = 1
        for i in 0..<len(s) {
            if s[i] == ' ' {
                res += 1
            }
        }
        return
    }

    res = make([]string, count(params), alloc) or_return
    pos, n: int

    for pos < len(params) {
        m := strings.index_byte(params[pos:], ' ')
        if m == -1 {
            break
        } else {
            res[n] = params[pos:pos+m]
            pos += m + 1
            n += 1
        }
    }

    if pos < len(params) {
        res[n] = params[pos:]
    }

    return
}


format_mess :: proc(mess: Message, buf: []u8) -> (res: string) {
    sb := strings.builder_from_bytes(buf)

    t_buf: [64]u8
    strings.write_string(&sb, time.to_string_hms_12(mess.recived, t_buf[:]))
    strings.write_bytes(&sb, {':', ' '})

    strings.write_string(&sb, reflect.enum_string(mess.sender.type))
    strings.write_bytes(&sb, {':', ' '})
    strings.write_string(&sb, mess.sender.name)

    if mess.cmd != "" {
        strings.write_byte(&sb, ' ')
        strings.write_string(&sb, mess.cmd)
        strings.write_byte(&sb, ':')

    } else if common.is_valid_code(mess.code) { 
        strings.write_byte(&sb, ' ')
        str := reflect.enum_string(mess.code)
        strings.write_string(&sb, str)

        if n := 17 - len(str); n > 0 {
            size := len(sb.buf)
            resize(&sb.buf, size + n)
            for i in size..<size+n {
                sb.buf[i] = ' '
            }
        }

        strings.write_byte(&sb, ':')

    } else {
        strings.write_string(&sb, " Invalid Code <")
        strings.write_int(&sb, int(mess.code))
        strings.write_string(&sb, ">")
    }

    if len(mess.params) > 0 {
        for p in mess.params {
            strings.write_byte(&sb, ' ')
            strings.write_string(&sb, p)
        }
    }

    if mess.tail != "" {
        strings.write_bytes(&sb, {' ', ':'})
        strings.write_string(&sb, mess.tail)
    }

    return strings.to_string(sb) 
}


print_mess :: proc(c: ^Client, mess: Message) -> (err: Error) {
    buf: [PRINT_BUFFER_SIZE]u8
    return print_str(c, format_mess(mess, buf[:]))
}

eprintln :: proc(c: ^Client, vals: ..any) -> (err: Error) {
    return print_str(c, fmt.tprintln(..vals), true)
}

println :: proc(c: ^Client, vals: ..any) -> (err: Error) {
    return print_str(c, fmt.tprintln(..vals))
}

print_str :: proc(c: ^Client, str: string, is_err := false) -> (err: Error) {
    buf: [PRINT_BUFFER_SIZE]u8
    
    n := copy(buf[:], CLEAR_LINE)
    n += copy(buf[n:], str)
    n += copy(buf[n:], "\n")
    n += copy(buf[n:], INPUT_STR)

    sync.guard(&c.mutex)
    if is_err {
        os.write(os.stderr, buf[:n]) or_return
    } else {
        os.write(os.stdout, buf[:n]) or_return
    }
    
    os.write(os.stdout, sa.slice(&c.input_buf)) or_return

    return
}



read_input :: proc(c: ^Client, buf: []byte) -> (res: string, err: Error) {
    in_stream := os.stream_from_handle(os.stdin)
    
    sync.lock(&c.mutex)
    os.write_string(os.stdout, CLEAR_LINE)
    os.write_string(os.stdout, INPUT_STR)
    sync.unlock(&c.mutex)

    loop: for {
        ch, sz := io.read_rune(in_stream) or_return
        for sync.atomic_load(&c.pause_input) {
            ch, sz = io.read_rune(in_stream) or_return
        }

        switch ch {
        case '\b':
            _, bs_sz := utf8.decode_last_rune_in_bytes(sa.slice(&c.input_buf))
            if bs_sz > 0 {
                sync.guard(&c.mutex)
                sa.consume(&c.input_buf, bs_sz)
                os.write_string(os.stdout, "\b\u0020\b") or_return
            }

        case '\n', '\r':
            // there's an issue with os.read skipping a character's bytes
            // if they're not read all at once
            // see: https://github.com/odin-lang/Odin/issues/4999#issuecomment-2779194161
            
            sync.guard(&c.mutex)
            n := copy(buf, sa.slice(&c.input_buf))
            sa.clear(&c.input_buf)
            os.write_string(os.stdout, CLEAR_LINE)

            res = string(buf[:n])
            break loop

        case:
            bytes, n := utf8.encode_rune(ch)

            sync.guard(&c.mutex)
            sa.append(&c.input_buf, ..bytes[:n])
            os.write(os.stdout, bytes[:n]) or_return
        }
    }

    return 
}

server_reconnect :: proc(c: ^Client) -> Error {
    for {
        server_err := join_server(c, c.server.url)
        if server_err == nil {
            break
        }

        if net_err, ok := server_err.(net.Network_Error); ok {
            #partial switch err in net_err {
            case net.Dial_Error:
                #partial switch err {
                case .Timeout, .Host_Unreachable, .Refused:
                    continue
                }

            case net.TCP_Recv_Error:
                if err == .Timeout {
                    continue
                }
            }
        }

        return server_err
    }
    return nil
}

recv_thread :: proc(c: ^Client) {
    if len(c.parsed) != 0 {
        for mess in c.parsed {
            print_mess(c, mess)
            destroy_message(mess, true)
        }
        clear(&c.parsed)
    }

    for !sync.atomic_load(&c.close_thread) {
        time.accurate_sleep(THREAD_TIMEOUT)

        if sync.atomic_load(&c.pause_thread) {
            sync.barrier_wait(&c.pause_barrier)

            for sync.atomic_load(&c.pause_thread) {
                time.accurate_sleep(THREAD_TIMEOUT)
            }
        }

        err := recv_data(c)
        if v, ok := err.(net.TCP_Recv_Error); ok && v == .Timeout {
            continue
        }
        if err != nil {
            tcp_err, ok := err.(net.TCP_Recv_Error)
            if !ok || tcp_err != .Connection_Closed {
                eprintln(c, "ERROR Can't Continue:", err)
                return
            }
            
            sync.atomic_store(&c.pause_input, true)
            println(c, "Server disconected. Attempting to reconnect.")

            recon_err := server_reconnect(c)
            if recon_err != nil {
                eprintln(c, "ERROR Can't Continue:", recon_err)
                return
            }

            println(c, "Reconnected to Server. Starting back up.")
            join_chan(c, c.chan)
            sync.atomic_store(&c.pause_input, false)
        }

        for c.net.pos > 0 {
            mess, m_err := parse_message(c)
            defer destroy_message(mess)

            if m_err != nil {
                eprintln(c, "ERROR:", err)
            
            } else if mess.cmd == "PING" {
                if len(mess.params) != 0 {
                    err = send_command(c.sock, "PONG ", mess.params[0], MESS_END_STR)
                } else {
                    err = send_command(c.sock, "PONG \r\n")
                }
                
                if err != nil {
                    eprintln(c, "ERROR:", err)
                } 

            } else {
                print_mess(c, mess)
            }

            pop_message(c, len(mess.raw))
        }
    }

    sync.barrier_wait(&c.close_barrier)
}


enable_raw_input :: proc() {
    _enable_raw_input()
}


disable_raw_input :: proc() {
    _disable_raw_input()
}

