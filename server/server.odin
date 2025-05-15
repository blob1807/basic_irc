package basic_irc_server

import "base:runtime"
import ir "base:intrinsics"

import "core:net"
import "core:log"
import "core:fmt"
import "core:mem"
import "core:sync"
import "core:time"
import "core:slice"
import "core:bytes"
import "core:crypto"
import "core:thread"
import "core:strings"
import "core:strconv"
import "core:reflect"
import "core:sync/chan"
import "core:mem/virtual"
import "core:time/timezone"

import com "../common"


// inits a server with default settings.
init_server :: proc(s: ^Server, addr: string, name := DEFAULT_NAME, network := DEFAULT_NETWORK, set_i_support := true) -> (err: Error) {
    s.name = name
    s.address = addr
    s.network = network
    s.onboard_timeout = ONBOARD_TIMEOUT
    s.timers.ping.duration = PING_TIMER_DURATION
    s.timers.ping_check.duration = PING_CHECK_TIMER_DURATION
    s.timers.client_cleanup.duration = CLIENT_CLEANUP_TIMER_DURATION

    if set_i_support {
        s.i_support = DEFAULT_I_SUPPORT
        s.i_support_str = strings.clone(DEFAULT_I_SUPPORT_STR) or_return
    }   

    s.info.tz, _ = timezone.region_load("local")
    s.info.version = VERSION

    return
}


server_cleanup :: proc(s: ^Server, free_i_support := true) {
    for _, &c in s.clients {
        destroy_user(c)
        free(c)
    }
    delete(s.clients)
    delete(s.nicks)

    for _, &c in s.channels {
        destroy_chan(c)
        free(c)
    }
    delete(s.channels)

    timezone.region_destroy(s.info.tz)

    if free_i_support {
        destroy_i_support(s)
    }
}


server_runner :: proc(s: ^Server) -> (err: Error) {
    context.random_generator = crypto.random_generator()

    temp_arena: virtual.Arena
    arena_error := virtual.arena_init_growing(&temp_arena)
    if arena_error != nil {
        log.fatal("Failed to create temporary arena in Server Runner because of: ", arena_error)
        return arena_error
    }

    context.temp_allocator = virtual.arena_allocator(&temp_arena)
    defer virtual.arena_destroy(&temp_arena)

    if s.address != "" {
        addr_ep, addr_ep_ok := net.parse_endpoint(s.address)
        if !addr_ep_ok {
            log.error("Failed to parse endpoint ", s.address)
            return
        }
        s.ep = addr_ep

    } else if s.ep == {} {
        s.ep = DEFAULT_ENDPOINT
    }    

    sock, sock_err := net.listen_tcp(s.ep)
    if sock_err != nil {
        log.errorf("TCP listen error on", s.address, sock_err)
        return
    }

    sock_err = net.set_option(sock, .Receive_Timeout, NET_RECEV_TIMEOUT)
    if sock_err != nil {
        log.errorf("Failed to set socket timeout", s.address, sock_err)
        return
    }

    s.sock = sock
    s.info.created = time.now()
    log.debug("Listening on endpoint", s.ep)

    if s.onboard_timeout == 0 {
        s.onboard_timeout = ONBOARD_TIMEOUT
    }

    {
        chan_name := strings.clone("#main")
        c_ptr := new(Channel)
        c_ptr^ = Channel {
            name  = chan_name, 
            users = make([dynamic]^Client, 0, 5),
            admin = make([dynamic]string, 0, 5),
        }

        s.channels[chan_name] = c_ptr

        start_barrier: sync.Barrier
        sync.barrier_init(&start_barrier, 2)
        c_ptr.thread = thread.create_and_start_with_poly_data3(s, c_ptr, &start_barrier, channel_thread)
        sync.barrier_wait(&start_barrier)
    }

    new_c_thread := thread.create_and_start_with_poly_data(s, open_new_clients_thread)
    log.debug("Connection opening thread started")

    start_timer(&s.timers.ping)
    start_timer(&s.timers.client_cleanup)
    log.infof("Sever (%v) started on %v", s.name, s.ep)

    for !sync.atomic_load(&s.close_server) {
        defer free_all(context.temp_allocator)
        // handle clients
        // handle channels
        // do pinging
        // free memory

        /*
        sync.lock(&s.client_lock)
        for k, &c in s.clients {
            // get data
            // send data
            // close client
            rb := &Response_Buffer {
                c.sock, 
                make([dynamic]u8, context.temp_allocator)
            }

            mess_loop: for c.flags & {.Close, .Quit} == {} {
                mess, m_err := get_message(s, c)

                #partial switch v in m_err {
                case nil:
                    to_upper(mess.cmd)
                    log.debugf("Received: \"%v\" gotten from \"%v\"; %q", mess.cmd, c.user, mess.raw)

                    switch mess.cmd {
                    case "INFO":    cmd_info(s, c, rb)
                    case "JOIN":    cmd_join(s, c, rb, mess)
                    case "KICK":    cmd_kick(s, c, rb, mess)
                    case "KILL":    cmd_kill(s, c, rb, mess)
                    case "LIST":    cmd_list(s, c, rb, mess)
                    case "LUSERS":  cmd_lusers(s, c, rb)
                    case "MOTD":    cmd_motd(s, c, rb)
                    case "NAMES":   cmd_names(s, c, rb, mess)
                    case "NICK":    cmd_nick(s, c, rb, mess)
                    case "PART":    cmd_part(s, c, rb, mess)
                    case "PING":    cmd_ping(s, c, rb, mess)
                    case "PONG":    cmd_pong(s, c, rb, mess)
                    case "PRIVMSG": cmd_privmsg(s, c, rb, mess)
                    case "TIME":    cmd_time(s, c, rb)
                    case "USER":    cmd_user(s, c, rb, mess)
                    case "VERSION": cmd_version(s, c, rb)
                    case "WHO":     cmd_who(s, c, rb, mess)
                    case "WHOIS":   cmd_whois(s, c, rb, mess)
                    case "QUIT": 
                        cmd_quit(s, c, rb, mess)
                        c.flags += {.Quit}
                        
                    case:
                        rb_cmd(rb, s.name, .ERR_UNKNOWNCOMMAND, c.user, ":Unsupported message type.", mess.cmd)
                    }

                    if mess.code != .None {
                        sb := strings.builder_make(context.temp_allocator)
                        strings.write_string(&sb, ":Unsupported message type. \"")
                        strings.write_string(&sb, reflect.enum_string(mess.code))
                        strings.write_byte(&sb, '"')
                        
                        rb_cmd(rb, s.name, .ERR_UNKNOWNCOMMAND, c.user, strings.to_string(sb))
                    }

                case IRC_Errors:
                    #partial switch v {
                    case .No_End_Of_Message:
                        rb_cmd_str(rb, s.name, "ERROR", c.user, ":No end of message was found.")
                    case .User_Mess_To_Big:
                        rb_cmd(rb, s.name, .ERR_INPUTTOOLONG, c.user, ":Input line was too long.")
                    }
                    if .Errored in c.flags {
                        c.flags += {.Close}
                    }
                    c.flags += {.Errored}

                case net.Network_Error:
                    tcp_err, ok := v.(net.TCP_Recv_Error)
                    if ok && tcp_err == .Timeout {
                        break mess_loop
                    }

                    log.error("Failed to get data from client", c.user, v)
                    if .Errored in c.flags {
                        c.flags += {.Close}
                    }
                    c.flags += {.Errored}

                case:
                    log.error("Failed to get data from client", c.user, m_err)
                    if .Errored in c.flags {
                        c.flags += {.Close}
                    }
                    c.flags += {.Errored}
                }
            }

            if len(rb.data) != 0 {
                log.debugf("Sending:  %q", string(rb.data[:]))
            }
            err = rb_send(rb)

            if .Pinging in s.flags {
                if .Pinged not_in c.flags {
                    hash: [128]u8
                    crypto.rand_bytes(hash[:])
                    
                    for &b in hash {
                        switch b {
                        case ' ', ':', '\r', '\n', '\x00':
                            b = '_'
                        }
                    }

                    rb_cmd_str(rb, s.name, "PING", string(hash[:]))

                    c.ping_token = strings.clone_from_bytes(hash[:])
                    c.flags += {.Pinged}
                }

            } else {
                if .Pinged in c.flags {
                    c.flags += {.Close}
                } 
            }
            
            if (Client_Flags{.Close, .Ping_Failed} & c.flags) != {} {
                rb_cmd_str(rb, s.name, "QUIT", c.user, ":QUIT: Server has closed your connection.")

                for ch in c.chans {
                    v, ok := s.channels[ch]
                    if ok {
                        append(&v.to_remove, c)

                        to_send := Message {
                            sender = {full=strings.clone(c.full, context.temp_allocator)},
                            cmd = "QUIT",
                            tail = ":QUIT: Sever has closed the connection.",
                        }
                        append(&v.to_send, to_send)
                    }
                }
                c.flags += {.Quit}
            }
        }
        sync.unlock(&s.client_lock)

        sync.lock(&s.channs_lock)
        for k, &c in s.channels {
            // remove users
            // propagate data

            for cl in c.to_remove {
                i, ok := slice.linear_search(c.users[:], cl)
                if ok {
                    unordered_remove(&c.users, i)
                }
            }
            clear(&c.to_remove)

            for m in c.to_send {
                #reverse for cl, pos in c.users { 
                    sync.guard(&s.client_lock)

                    if cl.user in s.clients {
                        if m.sender.full == cl.full {
                            continue
                        }
                        buf: []string 
                        
                        if m.tail == "" {
                            buf = make([]string, len(m.params), context.temp_allocator)
                        } else {
                            buf = make([]string, len(m.params) + 1, context.temp_allocator)
                            buf[len(buf) - 1] = m.tail
                        }

                        copy(buf, m.params)
                        log.debugf("Sending %v to %q", m, cl.user)
                        
                        if m.code != .None {
                            send_cmd(cl.sock, m.sender.full, m.code, ..buf)
                        } else {
                            send_cmd_str(cl.sock, m.sender.full, m.cmd, ..buf)
                        }

                    } else {
                        unordered_remove(&c.users, pos)
                    }
                }
                
            }
            clear(&c.to_send)
        }
        sync.unlock(&s.channs_lock)
        */

        if update_timer(&s.timers.client_cleanup) {
            sync.lock(&s.client_lock)
            for k, &c in s.clients {
                if .Quit in sync.atomic_load(&c.flags) || thread.is_done(c.thread) {
                    net.close(c.sock)
                    c.sock = 0

                    thread.terminate(c.thread, 0)
    
                    delete_key(&s.nicks, c.nick)
                    assert(c.nick not_in s.nicks)
    
                    delete(c.full)
                    delete(c.real)
                    delete(c.nick)
                    delete(c.ping_token)
    
                    free(c)
                    c = {}
    
                    delete_key(&s.clients, k)
                    assert(k not_in s.clients)
    
                    log.debug("User \"", k, "\"has been removed from the server", sep="")
                    delete(k) // k == c.user
                }
            }
            sync.unlock(&s.client_lock)

            reset_timer(&s.timers.client_cleanup)
        }
        
        if .Pinging not_in s.flags {
            if update_timer(&s.timers.ping) {
                reset_timer(&s.timers.ping_check)   
                s.flags += {.Pinging}
            }

        } else {
            if false && update_timer(&s.timers.ping_check) {
                reset_timer(&s.timers.ping)
                s.flags -= {.Pinging}
            } 
        }
    }

    sync.atomic_store(&s.close_new_client_thread, true)
    sync.atomic_store(&s.close_channel_threads, true)
    sync.atomic_store(&s.close_client_threads, true)

    s.sock = 0
    thread.terminate(new_c_thread, 0)
    thread.destroy(new_c_thread)

    for all_closed: bool; !all_closed; /**/ {
        all_closed = true
        for _, &c in s.clients {
            if .Has_Closed in sync.atomic_load(&c.thread_flags) {
                thread.destroy(c.thread)
                c.thread = nil
        
                send_cmd_str(c.sock, s.name, "QUIT", c.user, ":Server has closed.")
                net.close(c.sock)
                c.sock = 0

            } else {
                all_closed = false
            }
        }
        break
    }

    for all_closed: bool; !all_closed; /**/ {
        for _, &c in s.channels {
            if .Has_Closed in sync.atomic_load(&c.thread_flags) {
                thread.destroy(c.thread)
                c.thread = nil

            } else {
                all_closed = false
            }
        }
        break
    }
    

    server_cleanup(s)

    return 
}


open_new_clients_thread :: proc(s: ^Server) {
    context.logger = base_logger

    for !sync.atomic_load(&s.close_new_client_thread) {
        defer free_all(context.temp_allocator)

        c_sock, source, net_err := net.accept_tcp(s.sock)
        if net_err != nil {
            log.error("Failed to accept tcp connection.", net_err)
            continue
        }
        if sync.atomic_load(&s.close_new_client_thread) {
            break
        }

        log.debug("New connection", source)

        rb := &Response_Buffer {
            sock = c_sock,
            data = make([dynamic]u8, context.temp_allocator)
        }

        c := Client{sock=c_sock, ep=source}
        err := onboard_new_client(s, &c, rb)
        rb_err := rb_send(rb)

        if err != nil || rb_err != nil {
            log.errorf("Onboard Err: %v;  RB Err: %v;  Client: %v", err, rb_err, c)
            send_cmd_str(c.sock, s.name, "QUIT", c.user, ":Server has closed your connection.")
            net.close(c.sock)
            destroy_user(&c)
            continue
        }

        c.full = strings.concatenate({c.user, "!u@", s.name})
        c.flags += {.Registered}

        c_ptr := new_clone(c)

        sync.guard(&s.client_lock)
        sync.guard(&s.nick_lock)
        s.clients[c.user] = c_ptr
        s.nicks[c.nick] = c.user

        if len(s.clients) > s.stats.max_num_clients {
            s.stats.max_num_clients = len(s.clients)
        }
        
        start_barrier: sync.Barrier
        sync.barrier_init(&start_barrier, 2)
        c_ptr.thread = thread.create_and_start_with_poly_data3(s, c_ptr, &start_barrier, client_thread)
        sync.barrier_wait(&start_barrier)
        
        
        log.debug("New User", c)
    }
}


onboard_new_client :: proc(s: ^Server, c: ^Client, rb: ^Response_Buffer) -> (err: Error) {
    defer if err != nil && false {
        #partial switch v in err {
        case IRC_Errors:
            if v != .Message_To_Big && v != .Registration_Failed {
                send_cmd_str(c.sock, s.name, "ERROR", ":Unknown Server Error.")
            }
        case:
            send_cmd_str(c.sock, s.name, "ERROR", ":Unknown Server Error.")
        }
    }

    check_err :: proc(s: ^Server, c: ^Client, rb: ^Response_Buffer, err: Error) -> Error {
        #partial switch v in err {
        case IRC_Errors:
            if v == .User_Mess_To_Big {
                n := c.net_buf
                log.error("User message to long", c.net_buf, bytes.index(n.buf[n.read:n.pos], MESS_END))
                rb_cmd(rb, s.name, .ERR_INPUTTOOLONG, c.user, " :Input line was too long,") or_return
            }
        }
        return err
    }

    // https://modern.ircdocs.horse/#connection-registration
    got_cap: bool
    mess: Message
    err = recv_data(&c.net_buf, c.sock)
    if err != nil {
        log.error(c.net_buf)
        return
    }

    mess, err = parse_message(&c.net_buf, alloc = context.temp_allocator)
    if err != nil {
        return
    }

    // Capability Negotiation
    if mess.cmd == "CAP" {
        // ignore it
        mess, err = get_message(s, c)
        check_err(s, c, rb, err) or_return
        
        got_cap = true
        log.debug("Gotten Capability Negotiation. Ignoring.")
    }

    // Password
    if mess.cmd == "PASS" {
        // ignore it
        mess, err = get_message(s, c)
        check_err(s, c, rb, err) or_return
    } 
    
    // User & Nick
    start := time.tick_now()
    cmds: bit_set[enum{Nick, User}]

    loop: for time.tick_since(start) <= s.onboard_timeout {
        switch mess.cmd {
        case "NICK":
            cmd_nick(s, c, rb, mess)
            rb_send(rb)

            cmds += {.Nick}
            start = time.tick_now()
            log.debug("NICK command gotten")
    
        case "USER":
            cmd_user(s, c, rb, mess)
            rb_send(rb)
            
            cmds += {.User}
            start = time.tick_now()
            log.debug("USER command gotten")
    
        case: 
            if cmds == {.Nick, .User} {
                break loop
            }
            send_cmd(c.sock, s.name, .ERR_NOTREGISTERED, "* :You need to register before you can use", mess.cmd)
        }

        if cmds == {.Nick, .User} {
            break
        }

        mess, err = get_message(s, c)
        if err = check_err(s, c, rb, err); err != nil {
            log.error(err, cmds)
            return
        }
    }


    if cmds != {.Nick, .User} {
        rb_cmd(rb, s.name, .ERR_NOTREGISTERED, "* :Registration failed. No USER or NICK message given")
        return IRC_Errors.Registration_Failed
    }
    if .Nick not_in cmds {
        rb_cmd(rb, s.name, .ERR_NOTREGISTERED, "* :Registration failed. No NICK message given")
        return IRC_Errors.Registration_Failed
    }
    if .User not_in cmds {
        rb_cmd(rb, s.name, .ERR_NOTREGISTERED, "* :Registration failed. No USER message given")
        return IRC_Errors.Registration_Failed
    }

    log.debug("Registration of", c.user, "successful")

    pop_net_buf(&c.net_buf)

    if got_cap {
        err := recv_data(&c.net_buf, c.sock)
        #partial switch v in err {
        case net.TCP_Recv_Error:
            #partial switch v {
            case .Timeout:
            case:
                return err
            }
        case nil:
            pop_net_buf(&c.net_buf, .First) or_return
        case:
            return err
        }
    }

    // RPL_WELCOME
    rb_cmd(rb, s.name, .RPL_WELCOME, c.user, ":Welcome,", c.nick) or_return

    // RPL_YOURHOST
    rb_cmd(rb, s.name, .RPL_YOURHOST, c.user, ":Your host is", s.name) or_return

    // RPL_CREATED
    dmy_buf, hms_buf: [16]u8
    dmy_str := time.to_string_dd_mm_yy(s.info.created, dmy_buf[:])
    hms_str := time.time_to_string_hms(s.info.created, hms_buf[:])
    rb_cmd(rb, s.name, .RPL_CREATED, c.user, ":This server was created at", dmy_str, hms_str) or_return

    // RPL_MYINFO
    rb_cmd(rb, s.name, .RPL_MYINFO, c.user, s.name, VERSION, USER_MODES, CHANNEL_MODES) or_return

    // RPL_ISUPPORT 
    rb_cmd(rb, s.name, .RPL_ISUPPORT, c.user, s.i_support_str) or_return

    // https://modern.ircdocs.horse/#lusers-message
    cmd_lusers(s, c, rb) or_return

    // https://modern.ircdocs.horse/#motd-message
    cmd_motd(s, c, rb) or_return

    // RPL_UMODEIS
    rb_cmd(rb, s.name, .RPL_UMODEIS, c.user, "+i") or_return
    
    return
}


client_thread :: proc(s: ^Server, c: ^Client, _start_barrier: ^sync.Barrier) {
    start_barrier := _start_barrier
    sync.barrier_wait(start_barrier)
    start_barrier = nil

    c.to_send_alloc = context.allocator // TODO: Move to another allocator???

    context.logger = base_logger

    defer {
        sync.atomic_or(&c.flags, {.Quit})
        sync.atomic_or(&c.thread_flags, {.Has_Closed})
    }

    log.infof("Client thread for \"%v\" has started.", c.full)

    for !sync.atomic_load(&s.close_client_threads) \ 
    && (.Quit not_in sync.atomic_load(&c.flags)) {

        defer free_all(context.temp_allocator)

        rb := &Response_Buffer {
            c.sock, 
            make([dynamic]u8, context.temp_allocator)
        }

        mess_loop: for sync.atomic_load(&c.flags) & {.Close, .Quit} == {} {
            mess, m_err := get_message(s, c)

            #partial switch v in m_err {
            case nil:
                to_upper(mess.cmd)
                log.debugf("Command \"%v\" gotten from \"%v\"", mess.cmd, c.user)

                switch mess.cmd {
                case "INFO":    cmd_info(s, c, rb)
                case "JOIN":    cmd_join(s, c, rb, mess)
                case "KICK":    cmd_kick(s, c, rb, mess)
                case "KILL":    cmd_kill(s, c, rb, mess)
                case "LIST":    cmd_list(s, c, rb, mess)
                case "LUSERS":  cmd_lusers(s, c, rb)
                case "MOTD":    cmd_motd(s, c, rb)
                case "NAMES":   cmd_names(s, c, rb, mess)
                case "NICK":    cmd_nick(s, c, rb, mess)
                case "PART":    cmd_part(s, c, rb, mess)
                case "PING":    cmd_ping(s, c, rb, mess)
                case "PONG":    cmd_pong(s, c, rb, mess)
                case "PRIVMSG": cmd_privmsg(s, c, rb, mess)
                case "TIME":    cmd_time(s, c, rb)
                case "USER":    cmd_user(s, c, rb, mess)
                case "VERSION": cmd_version(s, c, rb)
                case "WHO":     cmd_who(s, c, rb, mess)
                case "WHOIS":   cmd_whois(s, c, rb, mess)
                case "QUIT": 
                    cmd_quit(s, c, rb, mess)
                    sync.atomic_or(&c.flags, {.Quit})
                    
                case:
                    rb_cmd(rb, s.name, .ERR_UNKNOWNCOMMAND, c.user, ":Unsupported message type.", mess.cmd)
                }

                if mess.code != .None {
                    sb := strings.builder_make(context.temp_allocator)
                    strings.write_string(&sb, ":Unsupported message type. \"")
                    strings.write_string(&sb, reflect.enum_string(mess.code))
                    strings.write_byte(&sb, '"')
                    
                    rb_cmd(rb, s.name, .ERR_UNKNOWNCOMMAND, c.user, strings.to_string(sb))
                }

            case IRC_Errors:
                #partial switch v {
                case .No_End_Of_Message:
                    rb_cmd_str(rb, s.name, "ERROR", c.user, ":No end of message was found.")
                case .User_Mess_To_Big:
                    rb_cmd(rb, s.name, .ERR_INPUTTOOLONG, c.user, ":Input line was too long.")
                }
                if .Errored in c.flags {
                    sync.atomic_or(&c.flags, {.Close})
                }
                sync.atomic_or(&c.flags, {.Errored})

            case net.Network_Error:
                tcp_err, ok := v.(net.TCP_Recv_Error)
                if ok && tcp_err == .Timeout {
                    break mess_loop
                }

                log.error("Failed to get data from client", c.user, v)
                if .Errored in c.flags {
                    sync.atomic_or(&c.flags, {.Close})
                }
                sync.atomic_or(&c.flags, {.Errored})

            case:
                log.error("Failed to get data from client", c.user, m_err)
                if .Errored in c.flags {
                    sync.atomic_or(&c.flags, {.Close})
                }
                sync.atomic_or(&c.flags, {.Errored})
            }
        }

        err := rb_send(rb)

        sync.lock(&c.lock)
        for mess in c.to_send {
            rb_mess(rb, mess, context.temp_allocator)
            delete(mess.raw, c.to_send_alloc)
        }
        clear(&c.to_send)
        sync.unlock(&c.lock)


        if .Pinging in sync.atomic_load(&s.flags) {
            if .Pinged not_in sync.atomic_load(&c.flags) {
                hash: [128]u8
                crypto.rand_bytes(hash[:])
                
                for &b in hash {
                    switch b {
                    case ' ', ':', '\r', '\n', '\x00':
                        b = '_'
                    }
                }

                rb_cmd_str(rb, s.name, "PING", string(hash[:]))

                c.ping_token = strings.clone_from_bytes(hash[:])
                sync.atomic_or(&c.flags, {.Pinged})
            }

        } else if .Pinged in sync.atomic_load(&c.flags) {
            sync.atomic_or(&c.flags, {.Close})
        } 

        err = rb_send(rb)
        
        if (Client_Flags{.Close, .Ping_Failed} & sync.atomic_load(&c.flags)) != {} {
            rb_cmd_str(rb, s.name, "QUIT", c.user, ":QUIT: Server has closed your connection.")

            for ch in c.chans {
                sync.lock(&s.channs_lock)
                v, ok := s.channels[ch]
                sync.unlock(&s.channs_lock)

                if ok {
                    sync.guard(&v.lock)
                    append(&v.to_remove, c)

                    to_send := Message {
                        sender = {full=strings.clone(c.full, v.to_send_alloc)},
                        cmd = "QUIT",
                        tail = ":QUIT: Sever has closed the connection.",
                    }
                    append(&v.to_send, to_send)
                }
            }
        }
    }

    log.infof("Client thread for \"%v\" has ended.", c.full)
}


channel_thread :: proc(s: ^Server, c: ^Channel, _start_barrier: ^sync.Barrier) {
    start_barrier := _start_barrier
    sync.barrier_wait(start_barrier)
    start_barrier = nil

    c.to_send_alloc = context.allocator // TODO: Move to another allocator???
    context.logger = base_logger

    defer {
        sync.atomic_or(&c.flags, {.Close})
        sync.atomic_or(&c.thread_flags, {.Has_Closed})
    }

    log.infof("Channel thread for \"%v\" has started.", c.name)

    for !sync.atomic_load(&s.close_channel_threads) {
        defer free_all(context.temp_allocator)

        time.accurate_sleep(time.Millisecond * 50)

        sync.lock(&c.lock)

        for cl in c.to_remove {
            i, ok := slice.linear_search(c.users[:], cl)
            if ok {
                unordered_remove(&c.users, i)
            }
        }
        clear(&c.to_remove)

        #reverse for user, pos in c.users { 
            sync.guard(&user.lock)

            sync.lock(&s.client_lock)
            if user.user not_in s.clients {
                unordered_remove(&c.users, pos)
                sync.unlock(&s.client_lock)
                continue
            }
            sync.unlock(&s.client_lock)

            for mess in c.to_send {
                m := mess
                if m.raw == "" {
                    m.raw = format_message(mess, user.to_send_alloc)
                } else {
                    m.raw = strings.clone(mess.raw, user.to_send_alloc)
                }
                
                append(&user.to_send, m)
                delete(mess.raw, c.to_send_alloc)
            }
            
        }
        clear(&c.to_send)

        sync.unlock(&c.lock)

        if .Close in sync.atomic_load(&c.flags) {
            break
        }
    }

    log.infof("Channel thread for \"%v\" has ended.", c.name)
    
}


reset_net_buf :: proc(n: ^Net_Buffer, zero := false) {
    n.peek = 0
    n.read = 0
    n.pos  = 0

    if zero {
        mem.zero_explicit(&n.buf, len(n.buf))
    }
}

pop_net_buf :: proc(n: ^Net_Buffer, read_type: enum{None, First, Last, All} = .None) -> (err: Error) {
    if n.pos == 0 {
        n.read = 0
        n.peek = 0
        return
    }

    #partial switch read_type {
    case .All:
        i := bytes.last_index(n.buf[:n.pos], MESS_END)
        if i == -1 {
            return IRC_Errors.No_End_Of_Message
        }
        n.read = i + len(MESS_END)
    
    case .Last:
        i := bytes.last_index(n.buf[:n.pos], MESS_END)
        if i == -1 {
            return IRC_Errors.No_End_Of_Message
        }

        i = bytes.last_index(n.buf[:i], MESS_END)
        if i == -1 {
            return IRC_Errors.No_End_Of_Message
        }

        n.pos = i

    case .First:
        if i := bytes.index(n.buf[n.read:n.pos], MESS_END); i != -1 {
            if MESSAGE_SIZE < i { 
                return IRC_Errors.User_Mess_To_Big
            }
            n.read += i + len(MESS_END)
            
        } else {
            return IRC_Errors.No_End_Of_Message
        }
    } 

    if n.read != 0 {
        n.pos = copy(n.buf[:], n.buf[n.read:n.pos])
        n.read = 0
        n.peek = 0
    }

    return
}


peek_message :: proc(s: ^Server, c: ^Client, clone_mess := false) -> (mess: Message, err: Error) {
    mess, err = parse_message(&c.net_buf, context.temp_allocator, clone_mess, true)

    if v, ok := err.(IRC_Errors); ok && v == .User_Mess_To_Big {
        send_cmd(c.sock, s.name, .ERR_INPUTTOOLONG, c.user, " :Input line was too long") or_return
    }

    return
}


get_message :: proc(s: ^Server, c: ^Client, clone_mess := false) -> (mess: Message, err: Error) {
    if pop_net_buf(&c.net_buf) != nil || c.net_buf.pos == 0 {
        recv_data(&c.net_buf, c.sock) or_return
    }
    mess, err = parse_message(&c.net_buf, context.temp_allocator, clone_mess)
    return
}



send_bytes :: proc(sock: net.TCP_Socket, buf: []u8) -> Error {
    switch {
    case len(buf) <= 0:
        return nil
    case len(buf) > MESSAGE_SIZE:
        return IRC_Errors.Message_To_Big
    case string(buf[len(buf)-2:]) != MESS_END_STR:
        return IRC_Errors.No_End_Of_Message
    }

    n, err := net.send_tcp(sock, buf)
    assert(n == len(buf))
    return err
}


send_string :: proc(sock: net.TCP_Socket, mess: string) -> (err: Error) {
    return send_bytes(sock, transmute([]u8)mess)
}


send_message :: proc(sock: net.TCP_Socket, mess: Message) -> (err: Error) {
    str := mess.raw
    if str == "" {
        str = format_message(mess, context.temp_allocator)
    }
    return send_string(sock, str)
}


send_cmd_str :: proc(sock: net.TCP_Socket, source: string, cmd: string, params: ..string) -> (err: Error) {
    buf: [MESSAGE_SIZE]byte
    i: int

    if source != "" {
        buf[0] = ':'
        i = 1
        i += copy(buf[1:], source)
    
        buf[i] = ' '
        i += 1
    }

    i += copy(buf[i:], cmd)

    buf[i] = ' '
    i += 1

    for p in params { 
        if MESSAGE_SIZE-2 <= len(p) + i + 1 {
            return IRC_Errors.Message_To_Big
        }

        i += copy(buf[i:], p)
        buf[i] = ' '
        i += 1
    }

    i += copy(buf[i:], MESS_END)

    return send_bytes(sock, buf[:i])
}


send_cmd :: proc(sock: net.TCP_Socket, source: string, cmd: com.RC, params: ..string) -> (err: Error) {
    buf: [MESSAGE_SIZE]byte
    i: int

    if source != "" {
        buf[0] = ':'
        i = 1
        i += copy(buf[1:], source)
    
        buf[i] = ' '
        i += 1
    }

    if cmd != .None {
        s := strconv.append_uint(buf[i:], u64(cmd), 10)
        i += len(s)
    } else {
        s := strconv.append_uint(buf[i:], u64(com.RC.RPL_NONE), 10)
        i += len(s)
    }

    buf[i] = ' '
    i += 1

    for p in params { 
        if MESSAGE_SIZE-2 <= len(p) + i + 1 {
            return IRC_Errors.Message_To_Big
        }

        i += copy(buf[i:], p)
        buf[i] = ' '
        i += 1
    }

    i += copy(buf[i:], MESS_END)

    return send_bytes(sock, buf[:i])
}


rb_send :: proc(rb: ^Response_Buffer) -> Error {
    if len(rb.data) <= 0 {
        return nil
    }

    n, err := net.send_tcp(rb.sock, rb.data[:])
    assert(n == len(rb.data))

    if err == nil {
       clear(&rb.data)
    }

    return err
}

rb_cmd :: proc(rb: ^Response_Buffer, source: string, cmd: com.RC, params: ..string) -> (err: Error) {
    buf: [MESSAGE_SIZE]byte
    i: int

    if source != "" {
        buf[0] = ':'
        i = 1
        i += copy(buf[1:], source)
    
        buf[i] = ' '
        i += 1
    }

    if i > MESSAGE_SIZE-2 {
        return IRC_Errors.Message_To_Big
    }

    if cmd != .None {
        s := strconv.append_uint(buf[i:], u64(cmd), 10)
        i += len(s)
    } else {
        s := strconv.append_uint(buf[i:], u64(com.RC.RPL_NONE), 10)
        i += len(s)
    }

    if i > MESSAGE_SIZE - 2 {
        return IRC_Errors.Message_To_Big
    }

    if len(params) <= 0 {
        i += copy(buf[i:], MESS_END)
        _, err = append(&rb.data, ..buf[:i])
        return  
    }

    buf[i] = ' '
    i += 1

    for p in params { 
        if MESSAGE_SIZE-2 <= len(p) + i + 1 {
            return IRC_Errors.Message_To_Big
        }

        i += copy(buf[i:], p)
        buf[i] = ' '
        i += 1
    }

    i += copy(buf[i:], MESS_END)

    _, err = append(&rb.data, ..buf[:i])
    return
}

rb_cmd_str :: proc(rb: ^Response_Buffer, source: string, cmd: string, params: ..string) -> (err: Error) {
    buf: [MESSAGE_SIZE]byte
    i: int

    if source != "" {
        buf[0] = ':'
        i = 1
        i += copy(buf[1:], source)
    
        buf[i] = ' '
        i += 1
    }

    if i + len(cmd) > MESSAGE_SIZE-2 {
        return IRC_Errors.Message_To_Big
    }

    i += copy(buf[i:], cmd)

    if len(params) <= 0 {
        i += copy(buf[i:], MESS_END)
        append(&rb.data, ..buf[:i]) or_return
        return
    }

    buf[i] = ' '
    i += 1

    for p in params { 
        if MESSAGE_SIZE-2 <= len(p) + i + 1 {
            return IRC_Errors.Message_To_Big
        }

        i += copy(buf[i:], p)
        buf[i] = ' '
        i += 1
    }

    i += copy(buf[i:], MESS_END)
    _, err = append(&rb.data, ..buf[:i])

    return
}

rb_mess :: proc(rb: ^Response_Buffer, mess: Message, alloc: runtime.Allocator) -> (err: Error) {
    str := mess.raw
    if str == "" {
        str = format_message(mess, alloc)
    }
    
    if len(str) > MESSAGE_SIZE {
        return IRC_Errors.Message_To_Big
    }
    _, err = append(&rb.data, str)
    return
}



recv_data :: proc(n_buf: ^Net_Buffer, sock: net.TCP_Socket) -> (err: net.Network_Error) {
    buf: [NET_READ_SIZE]byte
    r: int

    for n_buf.pos < MAX_MESSAGE_SIZE {
        r, err = net.recv_tcp(sock, buf[:])

        if r > 0 {
            n_buf.pos += copy(n_buf.buf[n_buf.pos:], buf[:r])
        }

        if err != nil \
        || n_buf.pos == NET_BUFFER_SIZE \
        || bytes.contains(buf[:r], MESS_END) {
            break
        }
    }

    return
}


parse_message :: proc(n: ^Net_Buffer, alloc: runtime.Allocator, clone := false, peek := false) -> (mess: Message, err: Error) {
    context.allocator = alloc

    if peek {
        if n.peek < n.read {
            n.peek = n.read
        }

        if i := bytes.index(n.buf[n.peek:n.pos], MESS_END); i != -1 {
            if MESSAGE_SIZE < i {
                err = IRC_Errors.User_Mess_To_Big
                return
            }
    
            mess.raw = string(n.buf[:i])
            n.peek = i + len(MESS_END)
            
            if clone {
                mess.raw = strings.clone(mess.raw)
            }
            
        } else {
            err = IRC_Errors.No_End_Of_Message
            return
        }

    } else if i := bytes.index(n.buf[n.read:n.pos], MESS_END); i != -1 {
        if MESSAGE_SIZE < i {
            err = IRC_Errors.User_Mess_To_Big
            return
        }

        mess.raw = string(n.buf[:i])
        n.read = i + len(MESS_END)
        
        if clone {
            mess.raw = strings.clone(mess.raw)
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

    if s[0] == ' ' {
        for i: int; i < len(s); i += 1 {
            if s[i] != ' ' {
                s = s[i:]
                break
            }
        }
    }

    // Source Check
    if s[0] == ':' {
        i = strings.index_byte(s, ' ')
        sender := s[1:i]
        mess.sender.name = sender
        
        ai := strings.index_byte(sender, '!')
        if len(sender) <= ai {
            mess.sender.type = .Invalid

        } else if ai == -1 {
            mess.sender.type = .Server

        } else {
            bi := strings.index_byte(sender[ai:], '@')
            if len(sender[ai:]) <= bi {
                mess.sender.type = .Invalid

            } else if bi == -1 {
                mess.sender.type = .Server

            } else {
                mess.sender.type = .User
            }
        }

        mess.sender.full = s[:i]
        s = s[i+1:]
    }

    // Code or Command check
    i = strings.index_byte(s, ' ')
    if i == -1 {
        fmt.eprintln("Failed to parse Code or Command")

    } else if v, ok := strconv.parse_int(s[:i], 10); ok {
        mess.code = com.Response_Codes(v)
        s = s[i+1:]

    } else {
        mess.cmd = s[:i]
        s = s[i+1:]
    }

    i = strings.index(s, " :")

    if i == -1 {
        mess.params = parse_params(s, alloc) or_return
    } else {
        mess.params = parse_params(s[:i], alloc) or_return
        mess.tail = s[i+2:]
    }

    return
}


parse_params :: proc(params: string, alloc: runtime.Allocator) -> (res: []string, err: runtime.Allocator_Error) {
    // https://modern.ircdocs.horse/#parameters
    
    // FIXME: Params can be seperated by one or more spaces
    buf := make([dynamic]string, 0, 15, alloc) or_return
    _params := params

    for _params != "" {
        m := strings.index_byte(_params, ' ')
        if m == -1 {
            break
        }
        append(&buf, _params[:m])
        _params = strings.trim_left_space(_params[m:])
    }

    if _params != "" {
        append(&buf, params)
    }

    shrink(&buf)

    return buf[:], nil
}

format_message :: proc(mess: Message, alloc: runtime.Allocator) -> string {
    sb := strings.builder_make(0, 512, alloc)

    if mess.sender.full != "" {
        strings.write_byte(&sb, ':')
        strings.write_string(&sb, mess.sender.full)
        strings.write_byte(&sb, ' ')
    
    } else if mess.sender.type != .Invalid && mess.sender.type != .None {
        strings.write_byte(&sb, ':')
        strings.write_string(&sb, mess.sender.name)
        strings.write_byte(&sb, ' ')
    }

    if mess.cmd != "" {
        strings.write_string(&sb, mess.cmd)
        strings.write_byte(&sb, ' ')

    } else if mess.code != .None {
        strings.write_uint(&sb, uint(mess.code))
        strings.write_byte(&sb, ' ')

    } else {
        strings.write_uint(&sb, uint(com.RC.RPL_NONE))
        strings.write_byte(&sb, ' ')
    }

    for p in mess.params { 
        strings.write_string(&sb, p)
        strings.write_byte(&sb, ' ')
    }

    if mess.tail != "" {
        if mess.tail[0] != ':' {
            strings.write_byte(&sb, ':')
        }
        strings.write_string(&sb, mess.tail)
    
    } else {
        strings.pop_byte(&sb)
    }

    strings.write_bytes(&sb, MESS_END)
    return strings.to_string(sb)
}

