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
import "core:mem/virtual"
import "core:time/timezone"
import "core:encoding/uuid"

import com "../common"



// WARNING THIS WILL NOT DO ANY CLEAN UP!!! IT WILL CAUSE MEMORY LEAKS & LEAVE THREADS OPEN!!!
// Immediately returns `server_runner` with `IRC_Errors.Server_Force_Quit` at the start of the next cycle.
FORCE_QUIT_SERVER: bool = false

// Gracefully Closes Server. Will do clean up.  
// Stops main loop, eqvialte to setting `Server.close_server`.
FORCE_CLOSE_SERVER: bool = false




// zeros & inits a server with default settings.
init_server :: proc(
    s: ^Server, addr: string, 
    name := DEFAULT_NAME, network := DEFAULT_NETWORK, set_i_support := true,
    allocator := context.allocator, logger := context.logger,
) -> (err: Error) {
    context.allocator = allocator
    runtime.mem_zero(s, size_of(Server))

    s.name = name
    s.address = addr
    s.network = network
    s.onboard_timeout = ONBOARD_TIMEOUT
    s.client_limiter = DEFAULT_RATE_LIMITER
    s.timers.ping.duration = PING_TIMER_DURATION
    s.timers.ping_check.duration = PING_CHECK_TIMER_DURATION
    s.timers.client_cleanup.duration = CLIENT_CLEANUP_TIMER_DURATION

    if set_i_support {
        d := DEFAULT_I_SUPPORT
        s.i_support = DEFAULT_I_SUPPORT
        s.i_support.case_map   = strings.clone(d.case_map) or_return
        s.i_support.chan_types = strings.clone(d.chan_types) or_return
        s.i_support.network    = strings.clone(d.network) or_return
        s.i_support.status_msg = strings.clone(d.status_msg) or_return
        s.i_support_str        = strings.clone(DEFAULT_I_SUPPORT_STR) or_return
    }   

    s.info.tz, _ = timezone.region_load("local")
    s.info.version = VERSION

    s.base_alloc = allocator
    s.base_logger = logger

    return
}


server_cleanup :: proc(s: ^Server, free_i_support := true) {
    for _, c in s.clients {
        if c == nil {
            continue
        }

        destroy_client(c)
        free(c)
    }
    delete(s.clients)
    delete(s.nicks)

    for _, c in s.channels {
        if c == nil {
            continue
        }

        destroy_chan(c)
        free(c)
    }
    delete(s.channels)

    timezone.region_destroy(s.info.tz)

    if free_i_support {
        destroy_i_support(s)
    }
}


/*
    Used to run `server_runner` as a thread
*/
server_runner_thread :: proc(s: ^Server) {
    err := server_runner(s)
    if err != nil {
        log.error("Server Error:", err)
    }
}


/*
    Main Server proc.
*/
server_runner :: proc(s: ^Server) -> (err: Error) {

    // This is only done here because it's unknown if the proc will be in a thread or not
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
        log.info("Endpoint or Address not set. Using Default Endpoint.")
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
    s.open_connection_thread = new_c_thread
    log.debug("Connection opening thread started")

    start_timer(&s.timers.ping)
    start_timer(&s.timers.client_cleanup)
    log.infof("Sever (%v) started on %v", s.name, s.ep)

    for !sync.atomic_load(&s.close_server) && !FORCE_CLOSE_SERVER {
        if FORCE_QUIT_SERVER {
            return IRC_Errors.Server_Force_Quit
        }

        defer free_all(context.temp_allocator)

        if update_timer(&s.timers.client_cleanup) {
            sync.lock(&s.client_lock)
            for k, &c in s.clients {
                clean_up: bool

                if .Closeing in sync.atomic_load(&c.thread_flags) {
                    if c.cleanup_check_count >= 5 {
                        thread.terminate(c.thread, 0)
                        thread.destroy(c.thread)
                        clean_up = true
                        
                    } else {
                        c.cleanup_check_count += 1
                    }
                }

                if thread.is_done(c.thread) {
                    if .Has_Closed not_in sync.atomic_load(&c.thread_flags) {
                        clean_up = true
                    }
                    thread.destroy(c.thread)

                } else if .Quit in sync.atomic_load(&c.flags) {
                    if .Has_Closed in sync.atomic_load(&c.thread_flags) \
                    || c.cleanup_check_count >= 5 {
                        thread.terminate(c.thread, 0)
                        thread.destroy(c.thread)
                        clean_up = true
                        
                    } else {
                        c.cleanup_check_count += 1
                    }
                }

                if clean_up {
                    net.close(c.sock)
                    c.sock = 0
    
                    delete_key(&s.nicks, c.nick)
                    assert(c.nick not_in s.nicks)
    
                    delete(c.full)
                    delete(c.real)
                    delete(c.nick)
                    delete(c.chans)
                    delete(c.ping_token)

                    for mess in c.mess_cache {
                        destroy_message(mess)
                    }
                    delete(c.mess_cache)

                    sync.lock(&c.to_send_lock)
                    for mess in c.to_send {
                        destroy_message(mess)
                    }
                    delete(c.to_send)
                    sync.unlock(&c.to_send_lock)
    
                    delete_key(&s.clients, k)
                    assert(k not_in s.clients)
    
                    log.debug("User \"", k, "\"has been removed from the server", sep="")
                    delete(k) // k == c.user

                    mem.zero(c, size_of(Client))
                    free(c)
                    c = nil
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
            if update_timer(&s.timers.ping_check) {
                sync.lock(&s.client_lock)
                for _, &c in s.clients {
                    if .Pinged not_in sync.atomic_load(&c.flags) {
                        sync.atomic_add(&c.flags, {.Ping_Failed})
                    }
                }
                sync.unlock(&s.client_lock)

                reset_timer(&s.timers.ping)
                s.flags -= {.Pinging}
            } 
        }

        time.accurate_sleep(SERVER_THREAD_TIMEOUT)
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


/*
    Handles the accepting of new client connections & opening of client threads.
*/
open_new_clients_thread :: proc(s: ^Server) {
    assert(context.temp_allocator.procedure == runtime.default_temp_allocator_proc)
    set_thead_name("Open New CLients Thread", s.open_connection_thread)

    context.logger = s.base_logger
    context.allocator = s.base_alloc

    for !sync.atomic_load(&s.close_new_client_thread) {
        defer free_all(context.temp_allocator)

        c_sock, source, net_err := net.accept_tcp(s.sock)
        if net_err != nil {
            log.error("Failed to accept tcp connection. Socket \"%v\";; Source \"%v\";; Error \"%v\"", c_sock, source, net_err)
            continue
        }
        if sync.atomic_load(&s.close_new_client_thread) {
            break
        }

        log.debug("New connection", source)
        _c := Client { 
            sock=c_sock, 
            ep=source, 
            limiter=s.client_limiter,
        }
        c := new_clone(_c)
        
        start_barrier: sync.Barrier
        sync.barrier_init(&start_barrier, 2)
        c.thread = thread.create_and_start_with_poly_data3(s, c, &start_barrier, client_thread)
        sync.barrier_wait(&start_barrier)
        
    }
}


/*
    Handles the onboarding of a new client.
*/
onboard_new_client :: proc(s: ^Server, c: ^Client, rb: ^Response_Buffer) -> (err: Error) {
    defer if err != nil && false {
        #partial switch v in err {
        case IRC_Errors:
            #partial switch v {
            case .Message_To_Big, .Registration_Failed, .User_Mess_To_Big:
            case:
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
                when IRC_SERVER_DEBUG {
                    log.error(
                        "User message to long", 
                        c.net_buf, 
                        bytes.index(n.buf[n.read:n.pos], MESS_END)
                    )
                }
                rb_cmd(rb, s.name, .ERR_INPUTTOOLONG, c.user, " :Input line was too long,") or_return
            }
        }
        return err
    }

    // https://modern.ircdocs.horse/#connection-registration
    cap_mess: Maybe(Message)
    mess: Message
    err = recv_data(&c.net_buf, c.sock)
    if err != nil {
        return
    }

    mess, err = parse_message(&c.net_buf, context.temp_allocator)
    if err != nil {
        return
    }

    // Capability Negotiation
    if mess.cmd == "CAP" {
        cap_mess = clone_message(mess, context.temp_allocator) or_return
        mess, err = get_message(s, c, false, true)
        check_err(s, c, rb, err) or_return
    }

    // Password
    if mess.cmd == "PASS" {
        // ignore it, no data is preserved between sessions.
        mess, err = get_message(s, c, false, true)
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
    
        case "USER":
            cmd_user(s, c, rb, mess)
            rb_send(rb)
            
            cmds += {.User}
            start = time.tick_now()
    
        case: 
            if cmds == {.Nick, .User} {
                break loop
            }
            send_cmd(c.sock, s.name, .ERR_NOTREGISTERED, "* :You need to register before you can use", mess.cmd)
        }

        if cmds == {.Nick, .User} {
            break
        }

        mess, err = get_message(s, c, false, true)
        if err = check_err(s, c, rb, err); err != nil {
            return
        }
    }


    if cmds != {.Nick, .User} {
        rb_cmd(rb, s.name, .ERR_NOTREGISTERED, "* :Registration failed. No USER nor NICK message given")
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

    pop_net_buf(&c.net_buf)

    if _mess, ok := cap_mess.?; ok {
        when true {
            capability_negotiation(s, c, _mess) or_return

        } else {
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
    }

    log.debug("Registration of", c.user, "successful")

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


/*
    Client thread started for each client. 
    Handles onboarding & commuication between client and channels.
*/
client_thread :: proc(s: ^Server, c: ^Client, _start_barrier: ^sync.Barrier) {
    assert(context.temp_allocator.procedure == runtime.default_temp_allocator_proc)
    set_thead_name(fmt.tprint("Client Thread:", c.user), c.thread)

    start_barrier := _start_barrier
    sync.barrier_wait(start_barrier)
    start_barrier = nil

    context.allocator = s.base_alloc
    context.logger = s.base_logger

    c.to_send_alloc = s.base_alloc

    rb := &Response_Buffer {
        c.sock, 
        make([dynamic]u8, context.temp_allocator),
    }


    // ========= Client Onboarding =========

    onboard_err := onboard_new_client(s, c, rb)
    _, rb_err := rb_send(rb)

    if onboard_err != nil || rb_err != nil {
        when IRC_SERVER_DEBUG {
            log.errorf("Onboard Err: %v;;  RB Err: %v;;  Client: %v", onboard_err, rb_err, c)
        } else {
            log.errorf("Onboard Err: %v;;  RB Err: %v;;  Client: %v", onboard_err, rb_err, c.full)
        }
        if c.quit_mess != "" {
            send_cmd_str(c.sock, s.name, "QUIT", c.user, c.quit_mess)
        } else {
            send_cmd_str(c.sock, s.name, "QUIT", c.user, ":Server has closed your connection.")
        }
        
        net.close(c.sock)
        destroy_client(c)
        free(c, s.base_alloc)
        return
    }

    c.full = strings.concatenate({c.user, "!u@", s.name})
    c.flags += {.Registered}


    sync.lock(&s.client_lock)
    s.clients[c.user] = c
    sync.lock(&s.nick_lock)

    sync.unlock(&s.client_lock)
    s.nicks[c.nick] = c.user
    sync.unlock(&s.nick_lock)

    if len(s.clients) > s.stats.max_num_clients {
        s.stats.max_num_clients = len(s.clients)
    }

    log.debug("New User", c)
    defer {
        add_flags(&c.flags, Client_Flags{.Quit})
        add_flags(&c.thread_flags, Thread_Flags{.Has_Closed})
    }


    // ========= Client Runner =========

    log.infof("Client thread for %w has started.", c.full)

    main_loop: for !sync.atomic_load(&s.close_client_threads) \ 
    && (.Quit not_in sync.atomic_load(&c.flags)) {

        defer free_all(context.temp_allocator)

        time.accurate_sleep(CLIENT_THREAD_TIMEOUT)
        rb.data = make([dynamic]u8, context.temp_allocator)
        

        //mess_loop: for (sync.atomic_load(&c.flags) & {.Close, .Quit}) == nil {
        mess_loop: for !has_flags(&c.flags, Client_Flags{.Close, .Quit}) {
            if .Rate_Limited in sync.atomic_load(&c.flags) \
             && !rate_limiter_check(c.limiter) {
                remove_flags(&c.flags, Client_Flags{.Rate_Limited})
            }
            
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
                    clear(&c.chans)
                    rb_send(rb)
                    add_flags(&c.flags, Client_Flags{.Quit})
                    break main_loop
                    
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
                
                case .Rate_Limited:
                    if .Rate_Limited in sync.atomic_load(&c.flags) \
                    && rate_limiter_check(c.limiter) {
                        break mess_loop
                    }
                    log.debug("Rate limiting", c.user)

                    left := rate_limiter_time_left(c.limiter)
                    str := fmt.tprintf(":You are rate limited. Please wait %v before sending another message.", left)
                    rb_cmd(rb, s.name, .RPL_TRYAGAIN, c.user, str)
                    add_flags(&c.flags, Client_Flags{.Rate_Limited})
                    break mess_loop
                }

                if .Errored in c.flags {
                    add_flags(&c.flags, Client_Flags{.Close})
                }

                add_flags(&c.flags, Client_Flags{.Errored})

            case net.TCP_Recv_Error:
                if v == .Timeout {
                    break mess_loop
                }

                log.error("Failed to get data from client", c.user, v)
                if .Errored in c.flags {
                    add_flags(&c.flags, Client_Flags{.Close})
                }

                add_flags(&c.flags, Client_Flags{.Errored})

            case:
                log.error("Failed to get data from client", c.user, m_err)
                if .Errored in c.flags {
                    add_flags(&c.flags, Client_Flags{.Close})
                }

                add_flags(&c.flags, Client_Flags{.Errored})
            }
        }

        _, err := rb_send(rb)

        if sync.try_lock(&c.to_send_lock) {
            for mess in c.to_send {
                rb_mess(rb, mess, context.temp_allocator)
                delete(mess.raw, c.to_send_alloc)
            }
            clear(&c.to_send)
            sync.unlock(&c.to_send_lock)

            _, err = rb_send(rb)
        }

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

                send_cmd_str(c.sock, s.name, "PING", string(hash[:]))

                c.ping_token = strings.clone_from_bytes(hash[:])
                add_flags(&c.flags, Client_Flags{.Pinged})
            }

        } else if .Pinged in sync.atomic_load(&c.flags) {
            add_flags(&c.flags, Client_Flags{.Close})
        } 

        
        // if (Client_Flags{.Close, .Ping_Failed} & sync.atomic_load(&c.flags)) != nil {
        if has_flags(&c.flags, Client_Flags{.Close, .Ping_Failed}) {
            if c.quit_mess != "" {
                send_cmd_str(c.sock, s.name, "QUIT", c.user, c.quit_mess)
            } else {
                send_cmd_str(c.sock, s.name, "QUIT", c.user, ":QUIT: Server has closed your connection.")
            }
            

            for ch in c.chans {
                sync.lock(&s.channs_lock)
                chan, ok := s.channels[ch]
                sync.unlock(&s.channs_lock)

                if ok {
                    sync.guard(&chan.lock)
                    append(&chan.to_remove, c)

                    sync.guard(&chan.to_send_lock)
                    to_send := Message {
                        sender = {full=strings.clone(c.full, chan.to_send_alloc)},
                        cmd = "QUIT",
                        tail = ":QUIT: Sever has closed the connection.",
                    }
                    append(&chan.to_send, to_send)
                }
            }
            clear(&c.chans)

            break main_loop
        }
    }

    log.debug("Closing client:", c.user, c.flags)
    add_flags(&c.thread_flags, Thread_Flags{.Closeing})
    defer remove_flags(&c.thread_flags, Thread_Flags{.Closeing})

    sync.guard(&c.lock)
    sync.guard(&c.to_send_lock)

    net.close(c.sock)
    c.sock = 0

    context.allocator = s.base_alloc
    delete_key(&s.nicks, c.nick)
    assert(c.nick not_in s.nicks)

    delete(c.full)
    delete(c.real)
    delete(c.nick)
    delete(c.chans)
    delete(c.ping_token)

    for mess in c.mess_cache {
        destroy_message(mess)
    }
    delete(c.mess_cache)

    for mess in c.to_send {
        destroy_message(mess)
    }
    delete(c.to_send)

    sync.guard(&s.client_lock)
    delete_key(&s.clients, c.user)
    assert(c.user not_in s.clients)

    log.debug("User \"", c.user, "\" has been removed from the server", sep="")
    delete(c.user) 
    log.infof("Client thread for \"%v\" has ended.", c.full)

    mem.zero(c, size_of(Client))
    free(c, s.base_alloc)
    
}


/*
    Channel thread started for each channel. 
    Handles commuication between the channel and its clients.
*/
channel_thread :: proc(s: ^Server, c: ^Channel, _start_barrier: ^sync.Barrier) {
    assert(context.temp_allocator.procedure == runtime.default_temp_allocator_proc)
    set_thead_name(fmt.tprint("Channel Thread:", c.name), c.thread)

    start_barrier := _start_barrier
    sync.barrier_wait(start_barrier)
    start_barrier = nil

    context.allocator = s.base_alloc
    context.logger = s.base_logger

    c.to_send_alloc = s.base_alloc

    defer {
        add_flags(&c.flags, Channel_Flags{.Close})
        add_flags(&c.thread_flags, Thread_Flags{.Has_Closed})
    }

    log.infof("Channel thread for \"%v\" has started.", c.name)

    for !sync.atomic_load(&s.close_channel_threads) {
        defer free_all(context.temp_allocator)

        time.accurate_sleep(CHANNEL_THREAD_TIMEOUT)

        sync.guard(&c.lock)

        for cl in c.to_remove {
            i, ok := slice.linear_search(c.users[:], cl)
            if ok {
                unordered_remove(&c.users, i)
            }
        }
        clear(&c.to_remove)

        #reverse for user, pos in c.users { 
            if sync.try_lock(&s.client_lock) {
                defer sync.unlock(&s.client_lock)

                if user.user not_in s.clients || .Quit in sync.atomic_load(&user.flags) {
                    unordered_remove(&c.users, pos)   
                    continue
                }
            }
            

            if sync.try_lock(&user.lock) {
                sync.guard(&user.to_send_lock)
                for mess in c.to_send {
                    if mess.sender.full == user.full {
                        continue
                    }

                    m := mess
                    if m.raw == "" {
                        m.raw = format_message(mess, user.to_send_alloc)
                    } else {
                        m.raw = strings.clone(mess.raw, user.to_send_alloc)
                    }
                    
                    append(&user.to_send, m)
                    delete(mess.raw, c.to_send_alloc)
                }
                sync.unlock(&user.lock)
            }
            
        }
        clear(&c.to_send)

        if .Close in sync.atomic_load(&c.flags) {
            break
        }
    }

    log.infof("Channel thread for \"%v\" has ended.", c.name)
    
}


/*
    Handles capability negotiation. 
    Limited to sending a single poisoned value and checking it's not returned.
*/
capability_negotiation :: proc(s: ^Server, c: ^Client, in_mess: Message) -> Error  {    
    mess := in_mess
    rb := Response_Buffer{sock = c.sock}
    rb.data.allocator = context.temp_allocator

    poison_buf: [uuid.EXPECTED_LENGTH]u8
    poison := uuid.to_string_buffer(uuid.generate_v4(), poison_buf[:])
    to_lower(poison)

    for (poison in com.String_to_Capability_Map) {
        poison = uuid.to_string_buffer(uuid.generate_v4(), poison_buf[:])
        to_lower(poison)
    }

    when IRC_SERVER_DEBUG {
        log.debugf("User %q: Poisoned Capability %q", c.full, poison)
    }

    for {
        fmt.println(mess)
        done, err := cmd_cap(s, c, &rb, mess, poison)
        if err != nil {
            rb_send(&rb) or_return
            return err
        }

        rb_send(&rb) or_return
        if done { break }

        mess, err = get_message(s, c, false, true)
        if err != nil {
            return err
        }
    }
    return nil
}


send_bytes :: proc(sock: net.TCP_Socket, buf: []u8) -> (int, Error) {
    switch {
    case len(buf) <= 0:
        return 0, nil
    case len(buf) < 2:
        return 0, IRC_Errors.Not_Enough_Data
    case len(buf) > MESSAGE_SIZE:
        return 0, IRC_Errors.Message_To_Big
    }
    if string(buf[len(buf)-2:]) != MESS_END_STR {
        return 0, IRC_Errors.No_End_Of_Message
    }

    n, err := net.send_tcp(sock, buf)
    if err != nil {
        return 0, err
    }

    when IRC_SERVER_DEBUG {
        log.assertf (
            n == len(buf), 
            "Not all data sent;; %v != %v;; mess = %q;; sent = %q", 
            len(buf), n, string(buf), string(buf[:n]),
        )
    }

    return n, nil if n == len(buf) else IRC_Errors.Failed_To_Send_Message
}


send_string :: proc(sock: net.TCP_Socket, mess: string) -> (n: int, err: Error) {
    return send_bytes(sock, transmute([]u8)mess)
}


send_message :: proc(sock: net.TCP_Socket, mess: Message) -> (n: int, err: Error) {
    str := mess.raw
    if str == "" {
        str = format_message(mess, context.temp_allocator)
    }
    return send_string(sock, str)
}


send_cmd_str :: proc(sock: net.TCP_Socket, source: string, cmd: string, params: ..string) -> (n: int, err: Error) {
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
            return 0, IRC_Errors.Message_To_Big
        }

        i += copy(buf[i:], p)
        buf[i] = ' '
        i += 1
    }

    i += copy(buf[i:], MESS_END)

    return send_bytes(sock, buf[:i])
}


send_cmd :: proc(sock: net.TCP_Socket, source: string, cmd: com.RC, params: ..string) -> (n: int, err: Error) {
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
        s := strconv.write_uint(buf[i:], u64(cmd), 10)
        i += len(s)
    } else {
        s := strconv.write_uint(buf[i:], u64(com.RC.RPL_NONE), 10)
        i += len(s)
    }

    buf[i] = ' '
    i += 1

    for p in params { 
        if MESSAGE_SIZE-2 <= len(p) + i + 1 {
            return 0, IRC_Errors.Message_To_Big
        }

        i += copy(buf[i:], p)
        buf[i] = ' '
        i += 1
    }

    i += copy(buf[i:], MESS_END)

    return send_bytes(sock, buf[:i])
}


rb_send :: proc(rb: ^Response_Buffer) -> (int, Error) {
    switch {
    case len(rb.data) <= 0:
        return 0, nil
    case len(rb.data) < 2:
        return 0, IRC_Errors.Not_Enough_Data
    case string(rb.data[len(rb.data)-2:]) != MESS_END_STR:
        return 0, IRC_Errors.No_End_Of_Message
    }

    n, err := net.send_tcp(rb.sock, rb.data[:])
    if err != nil {
        return 0, err
    }

    when IRC_SERVER_DEBUG {
        log.assertf (
            n == len(rb.data), 
            "Not all data sent;; %v != %v;; mess = %q;; sent = %q", 
            len(rb.data), n, string(rb.data[:]), string(rb.data[:n]),
        )
    }

    clear(&rb.data)

    return n, nil
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
        s := strconv.write_uint(buf[i:], u64(cmd), 10)
        i += len(s)
    } else {
        s := strconv.write_uint(buf[i:], u64(com.RC.RPL_NONE), 10)
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


/*
    Receives data from a socket until an error, end of message found or buffer is full.
*/
recv_data :: proc(n_buf: ^Net_Buffer, sock: net.TCP_Socket) -> (err: net.TCP_Recv_Error) {
    buf: [NET_READ_SIZE]byte
    r: int

    for n_buf.pos < MAX_MESSAGE_SIZE {
        r, err = net.recv_tcp(sock, buf[:])

        if 0 < r {
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


reset_net_buf :: proc(n: ^Net_Buffer, zero := false) {
    n.read = 0
    n.pos  = 0

    if zero {
        mem.zero_explicit(&n.buf, len(n.buf))
    }
}


/*
    Pops a message off the front based on `read_mode`:
        `.None` : just uses whats in `n.pos` already
        `.First`: finds and pops the first 
        `.Last` : finds and pops all but the last
        `.All`  : pops messages
    `IRC_Errors.No_End_Of_Message` is returned if no `MESS_END` found 
*/
pop_net_buf :: proc(n: ^Net_Buffer, read_mode: enum{None, First, Last, All} = .None) -> (err: Error) {
    if n.pos == 0 {
        n.read = 0
        return
    }

    #partial switch read_mode {
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
            i = 0
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
    }

    return
}


/*
    Gets & Parses a message from the Client.
    Rate limits the Client.
*/
get_message :: proc(s: ^Server, c: ^Client, clone_mess := false, ignore_limit := false) -> (mess: Message, err: Error) {
    if pop_net_buf(&c.net_buf) != nil || c.net_buf.pos == 0 {
        recv_data(&c.net_buf, c.sock) or_return
    }

    if !ignore_limit && rate_limiter_update(&c.limiter) {
        err = .Rate_Limited
        return
    }

    mess, err = parse_message(&c.net_buf, context.temp_allocator, clone_mess)
    return
}


index_message :: proc(n: ^Net_Buffer, consume := true) -> (pos: int, err: Error) {
    if i := bytes.index(n.buf[n.read:n.pos], MESS_END); i != -1 {
        if MESSAGE_SIZE < i {
            return 0, IRC_Errors.User_Mess_To_Big
        }

        pos = i
        if consume { n.read = i + len(MESS_END) } 
        
    } else {
        return 0, IRC_Errors.No_End_Of_Message
    }
    
    return 
}


parse_message :: proc{parse_message_str, parse_message_net_buf}


parse_message_net_buf :: proc(n: ^Net_Buffer, alloc: runtime.Allocator, clone := false) -> (mess: Message, err: Error) {
    idx := index_message(n) or_return
    return parse_message_str(string(n.buf[:idx]), alloc, clone)
}


parse_message_str :: proc(str: string, alloc: runtime.Allocator, clone := false) -> (mess: Message, err: runtime.Allocator_Error) {
    mess.raw = clone ? strings.clone(str) or_return : str
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
        for n: int; n < len(s); n += 1 {
            if s[n] != ' ' {
                s = s[n:]
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

    if s == "" {
        log.errorf("Failed to parse Code or Command: %q", mess.raw)
        return
    }

    // Code or Command check
    i = strings.index_byte(s, ' ')
    if i == -1 {
        mess.cmd = s

    } else if v, ok := strconv.parse_int(s[:i], 10); ok {
        mess.code = com.Response_Code(v)
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
        append(&buf, _params)
    }

    shrink(&buf)

    return buf[:], nil
}


clone_message :: proc(mess: Message, alloc: runtime.Allocator) -> (res: Message, err: runtime.Allocator_Error) {
    return parse_message(mess.raw, alloc, true)
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
    shrink(&sb.buf)
    return strings.to_string(sb)
}
