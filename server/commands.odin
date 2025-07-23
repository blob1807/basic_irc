package basic_irc_server


import "core:log"
import "core:net"
import "core:time"
import "core:sync"
import "core:slice"
import "core:strconv"
import "core:strings"
import "core:time/timezone"

@(require) import "core:fmt"

import com "../common"


cmd_info :: proc(s: ^Server, c: ^Client, rb: ^Response_Buffer) -> (err: Error) {
    // https://modern.ircdocs.horse/#info-message
    st := format_server_time(s.info.tz, context.temp_allocator)

    rb_cmd(rb, s.name, .RPL_INFO, c.nick, ":Server Version " + VERSION)
    rb_cmd(rb, s.name, .RPL_INFO, c.nick, ":Server Time", st)
    rb_cmd(rb, s.name, .RPL_INFO, c.nick, ":Created by blob1807")
    rb_cmd(rb, s.name, .RPL_INFO, c.nick, ":Main repo https://github.com/blob1807/basic_irc")
    rb_cmd(rb, s.name, .RPL_ENDOFINFO, c.nick, ":End of /INFO")
    
    return 
}


cmd_join :: proc(s: ^Server, c: ^Client, rb: ^Response_Buffer, mess: Message) -> (err: Error) {
    if len(mess.params) <= 0 {
        return rb_cmd(rb, s.name, .ERR_NEEDMOREPARAMS, c.nick, ":No channels were provided")
    }

    chans := mess.params[0]

    for chan in strings.split_after_iterator(&chans, ",") {
        if s.chan_limit.limit != -1 && len(c.chans) < s.chan_limit.limit {
            rb_cmd(rb, s.name, .ERR_TOOMANYCHANNELS, c.nick, chan, ":You have joined too many channels") or_return
            break
        }

        sync.lock(&s.channs_lock)
        ch, ok := s.channels[chan]
        if !ok {
            rb_cmd(rb, s.name, .ERR_NOSUCHCHANNEL, c.nick, chan, ":no such channel") or_return
            continue
        }

        if .Client_Limit in ch.modes && len(ch.users) >= ch.user_limit {
            rb_cmd(rb, s.name, .ERR_CHANNELISFULL, c.nick, chan, ":Cannot join channel (+l)") or_return
            continue
        }
        chan_clone := strings.clone(chan)

        out := Message {
            cmd = "JOIN",
            sender = {full = c.full,  type = .User},
            params = make([]string, 1, ch.to_send_alloc) ,
        }
        out.params[0] = chan_clone

        sync.lock(&ch.lock)
        append(&ch.users, c) 
        sync.unlock(&ch.lock)

        try_to_send_to_chan(c, ch, out)
        
        append(&c.chans, chan_clone)
        sync.unlock(&s.channs_lock)

        rb_mess(rb, out, context.temp_allocator) or_return

        cmd_names(s, c, rb, Message{params={chan}})
    }

    return
}


cmd_kick :: proc(s: ^Server, c: ^Client, rb: ^Response_Buffer, mess: Message) -> (err: Error) {
    // https://modern.ircdocs.horse/#kick-message

    if len(mess.params) < 2 {
        return rb_cmd(rb, s.name, .ERR_NEEDMOREPARAMS, c.nick, ":No channel & user provied.")
    }

    chan_name := mess.params[0]

    if !slice.contains(c.chans[:], chan_name) {
        return rb_cmd(rb, s.name, .ERR_NOTONCHANNEL, c.nick, chan_name, ":No in channel")
    }

    sync.lock(&s.channs_lock)
    chan, ok := s.channels[chan_name]
    sync.unlock(&s.channs_lock)

    if !ok {
        return rb_cmd(rb, s.name, .ERR_NOSUCHCHANNEL, c.nick, chan_name, ":No such channel")
    }

    sync.guard(&chan.lock)
    if !slice.contains(chan.admin[:], c.user) {
        return rb_cmd(rb, s.name, .ERR_CHANOPRIVSNEEDED, c.nick, chan_name, ":You're not channel operator")
    }

    users := mess.params[1]
    comment := mess.tail != "" ? mess.tail : ":User has been kicked."

    sync.guard(&s.client_lock)
    for user in strings.split_after_iterator(&users, ",") {
        cl, cl_ok := s.clients[user]
        if !cl_ok || !slice.contains(chan.users[:], cl) {
            rb_cmd(rb, s.name, .ERR_USERNOTINCHANNEL, c.nick, user, chan_name, ":They aren't on that channe")
            continue
        }
        append(&chan.to_remove, cl)

        // TODO: Do I need to propergate the message?

        rb_cmd_str(rb, c.nick, "KICK", chan_name, user, comment)
    }

    return
}


cmd_kill :: proc(s: ^Server, c: ^Client, rb: ^Response_Buffer, mess: Message) -> (err: Error) {
    // TODO: https://modern.ircdocs.horse/#kill-message
    return rb_cmd_str(rb, s.name, "ERROR", c.nick, ":Command", mess.cmd, "is currently WIP.")
}


cmd_list :: proc(s: ^Server, c: ^Client, rb: ^Response_Buffer, mess: Message) -> (err: Error) {

    if len(mess.params) == 0 || len(s.channels) == 0 {
        return rb_cmd(rb, s.name, .RPL_LISTEND, c.nick, ":End of /LIST")
    }

    names := mess.params[0]
    rb_cmd(rb, s.name, .RPL_LISTSTART, c.nick, "Channel :Users Name")

    sync.guard(&s.channs_lock)
    for name in strings.split_after_iterator(&names, ",") {
        if len(name) == 0 || name[0] != '#' {
            continue
        }

        chan := s.channels[name] or_continue
        sync.guard(&chan.to_send_lock)
        
        buf: [20]u8
        str := strconv.write_int(buf[:], i64(len(chan.users)), 10)
        rb_cmd(rb, s.name, .RPL_LIST, c.nick, chan.name, str)
    }
    rb_cmd(rb, s.name, .RPL_LISTEND, c.nick, ":End of /LIST")

    return 
}


cmd_lusers :: proc(s: ^Server, c: ^Client, rb: ^Response_Buffer) -> (err: Error) {
    buf: [128]u8
    pos, t_pos: int

    ops, invis: i64

    users := i64(len(s.clients))
    chans := i64(len(s.channels))

    for _, v in s.clients {
        if .Op in v.flags {
            ops += 1
        }
        if .Invisable in v.flags {
            invis += 1
        }
    }

    pos = copy(buf[:], ":There are ")
    pos += len(strconv.write_int(buf[pos:], users, 10))
    pos += copy(buf[pos:], " users and ")
    pos += len(strconv.write_int(buf[pos:], invis, 10))
    pos += copy(buf[pos:], " on 1 server.")
    rb_cmd(rb, s.name, .RPL_LUSERCLIENT, c.nick, string(buf[:pos])) or_return


    pos = len(strconv.write_int(buf[:], ops, 10))
    pos += copy(buf[pos:], " :operators online.")
    rb_cmd(rb, s.name, .RPL_LUSEROP, c.nick, string(buf[:pos])) or_return

    rb_cmd(rb, s.name, .RPL_LUSERUNKNOWN, c.nick, "0 :unknown connections.") or_return


    pos = len(strconv.write_int(buf[:], chans, 10))
    pos += copy(buf[pos:], " :channels formed.")
    rb_cmd(rb, s.name, .RPL_LUSERCHANNELS, c.nick, string(buf[:pos])) or_return


    pos = copy(buf[:], ":I have ")
    pos += len(strconv.write_int(buf[:], users, 10))
    pos += copy(buf[pos:], " clients and 1 server.")
    rb_cmd(rb, s.name, .RPL_LUSERME, c.nick, string(buf[:pos])) or_return


    pos = len(strconv.write_int(buf[:], users, 10))
    buf[pos] = ' '; pos += 1
    pos += len(strconv.write_int(buf[pos:], i64(s.stats.max_num_clients), 10))
    t_pos = pos + 10 // len(" :Current ")
    pos += copy(buf[pos:], " :Current local users ")
    pos += len(strconv.write_int(buf[:], users, 10))
    pos += copy(buf[pos:], " , max ")
    pos += len(strconv.write_int(buf[pos:], i64(s.stats.max_num_clients), 10))
    pos += 1
    rb_cmd(rb, s.name, .RPL_LOCALUSERS, c.nick, string(buf[:pos])) or_return


    pos = t_pos
    pos += copy(buf[pos:], "global users ") // use " :Current " from above
    pos += len(strconv.write_int(buf[:], users, 10))
    pos += copy(buf[pos:], " , max ")
    pos += len(strconv.write_int(buf[pos:], i64(s.stats.max_num_clients), 10))
    pos += 1
    rb_cmd(rb, s.name, .RPL_GLOBALUSERS, c.nick, string(buf[:pos])) or_return

    return 
}


cmd_motd :: proc(s: ^Server, c: ^Client, rb: ^Response_Buffer) -> (err: Error) {
    rb_cmd(rb, s.name, .RPL_MOTDSTART, c.nick, ":G'day") or_return
    rb_cmd(rb, s.name, .RPL_MOTD, c.nick, ":AHHHHH") or_return
    rb_cmd(rb, s.name, .RPL_ENDOFMOTD, c.nick, ":G'bye") or_return
    return
}


cmd_names :: proc(s: ^Server, c: ^Client, rb: ^Response_Buffer, mess: Message) -> (err: Error) {
    names: []string
    if len(mess.params) != 0 {
        names = strings.split(mess.params[0], ",", context.temp_allocator) or_return
    }
    
    if len(names) == 0 || len(s.channels) == 0 {
        rb_cmd(rb, s.name, .RPL_ENDOFNAMES, c.nick, "*", ":End of /NAMES list") or_return
        return
    }

    if len(names) > s.max_targets {
        names = names[:s.max_targets]
    }

    sb := strings.builder_make(context.temp_allocator) or_return

    for name in names {
        sync.guard(&s.channs_lock)
        chan, ok := s.channels[name]

        if !ok || len(name) == 0 || name[0] != '#' {
            rb_cmd(rb, s.name, .RPL_ENDOFNAMES, c.nick, name, ":End of /NAMES list") or_return
            continue
        }

        to_send := Message {
            sender = {full=s.name},
            code   = .RPL_NAMREPLY,
            params = {c.nick, "=", name},
        }

        to_send.raw = format_message(to_send, context.temp_allocator)
        left := MESSAGE_SIZE - len(to_send.raw)
        
        pos: int
        sync.guard(&s.client_lock)
        sync.guard(&chan.lock)

        for pos < len(chan.users) {
            strings.write_byte(&sb, ':')

            for /**/; pos < len(chan.users); pos += 1 {
                user := chan.users[pos]
                cl_ok := user.user in s.clients

                if cl_ok && .Invisable not_in user.flags {
                    if len(sb.buf) + len(user.full) + 1 > left {
                        break
                    }
                    strings.write_string(&sb, user.full)
                    strings.write_byte(&sb, ' ')
                }
            }

            strings.pop_byte(&sb)

            str := strings.to_string(sb)
            rb_cmd(rb, s.name, .RPL_NAMREPLY, c.nick, "=", name, str)
            strings.builder_reset(&sb)
        }

        rb_cmd(rb, s.name, .RPL_ENDOFNAMES, c.nick, name, ":End of /NAMES list")
    }

    return
}


cmd_nick :: proc(s: ^Server, c: ^Client, rb: ^Response_Buffer, mess: Message) -> (err: Error) {
    if len(mess.params) == 0 {
        rb_cmd(rb, s.name, .ERR_NONICKNAMEGIVEN, "* :No nickname given.") or_return
        return
    }
    nick := mess.params[0]
    to_lower(nick)

    if len(nick) > s.i_support.nick_len || !com.is_valid_nick(nick) {
        rb_cmd(rb, s.name, .ERR_ERRONEUSNICKNAME, "*", nick, ":Invalid nickname was given") or_return
        return
    }
    if nick in s.nicks && c.nick != nick {
        rb_cmd(rb, s.name, .ERR_NICKNAMEINUSE, "*", nick, ":Nickname is already in use")
        return
    }

    c.nick = strings.clone(nick, s.base_alloc)
    return
}


cmd_part :: proc(s: ^Server, c: ^Client, rb: ^Response_Buffer, mess: Message) -> (err: Error) {
    if len(mess.params) == 0 {
        return rb_cmd(rb, s.name, .ERR_NEEDMOREPARAMS, c.nick, "PART :Not enough parameters")
    }

    reason: string
    if len(mess.params) == 2 {
        reason = strings.clone(mess.params[1], context.temp_allocator) or_return
    }

    names := mess.params[0]

    for name in strings.split_after_iterator(&names, ",") {
        i, found := slice.linear_search(c.chans[:], name)
        if !found {
            rb_cmd(rb, s.name, .ERR_NOTONCHANNEL, c.nick, name, ":You're not on that channel") or_return
            continue
        }

        sync.guard(&s.channs_lock)
        chan, chan_ok := s.channels[name]

        if !chan_ok {
            rb_cmd(rb, s.name, .ERR_NOSUCHCHANNEL, c.nick, name, ":No such channel") or_return
            continue
        }

        to_send := Message{
            sender = {full = c.full, type = .User},
            cmd = "PART",
            params = make([]string, 2, chan.to_send_alloc),
        }
        to_send.params[0] = chan.name

        if reason != "" {
            to_send.params[1] = reason
        }

        rb_mess(rb, to_send, context.temp_allocator)

        try_to_send_to_chan(c, chan, to_send)
        
        append(&chan.to_remove, c)
        unordered_remove(&c.chans, i)
    }

    return
}


cmd_ping :: proc(s: ^Server, c: ^Client, rb: ^Response_Buffer, mess: Message) -> (err: Error) {
    if len(mess.params) == 0 {
        rb_cmd_str(rb, s.name, "PONG", s.name) or_return
    } else {
        rb_cmd_str(rb, s.name, "PONG", s.name, mess.params[0]) or_return
    }

    err = recv_data(&c.net_buf, c.sock)

    #partial switch v in err {
    case net.Network_Error:
        #partial switch e in v {
        case net.TCP_Recv_Error:
            #partial switch e {
            case .Timeout:
                err = nil
            }
        }
    }

    return 
}


cmd_pong :: proc(s: ^Server, c: ^Client, rb: ^Response_Buffer, mess: Message) -> (err: Error) {
    if .Pinged in c.flags {
        if len(mess.params) == 0 || mess.params[0] != c.ping_token {
            c.flags += {.Ping_Failed}
        }

        c.flags -= {.Pinged}
        delete(c.ping_token)
    }
    return
}


cmd_privmsg :: proc(s: ^Server, c: ^Client, rb: ^Response_Buffer, mess: Message) -> (err: Error) {
    if len(mess.params) <= 0 {
        return rb_cmd(rb, s.name, .ERR_NORECIPIENT, c.nick, ":No recipient given (PRIVMSG)")
    }

    if mess.params[0] == "" {
        return rb_cmd(rb, s.name, .ERR_NORECIPIENT, c.nick, ":No recipient given (PRIVMSG)")
    } if mess.tail == "" {
        return rb_cmd(rb, s.name, .ERR_NOTEXTTOSEND, c.nick, ":No text to send")
    }

    targets := strings.split(mess.params[0], ",", context.temp_allocator) or_return
    if len(targets) > s.max_targets {
        return rb_cmd(rb, s.name, .ERR_TOOMANYTARGETS, c.nick, ":Too many targets (PRIVMSG)")
    }
    
    to_send := Message {
        sender = {full = c.full, type = .User},
        cmd = "PRIVMSG",
    }

    tail := mess.tail
    if tail != "" && tail[0] != ':' {
        tail = strings.concatenate({":", tail}, context.temp_allocator)
    }

    for tar in targets {
        if tar == "" {
            continue
        }

        if !slice.contains(c.chans[:], tar) {
            rb_cmd(rb, s.name, .ERR_CANNOTSENDTOCHAN, c.nick, tar, ":Cannot send to channel")
            continue
        }
        
        sync.lock(&s.channs_lock)
        chan, ok := s.channels[tar]
        sync.unlock(&s.channs_lock)

        if !ok {
            rb_cmd(rb, s.name, .ERR_NOSUCHCHANNEL, c.nick, tar, ":Cannot send to channel")
            continue
        }

        to_send.params = make([]string, 1, chan.to_send_alloc)
        to_send.params[0] = chan.name
        to_send.tail = strings.clone(tail, chan.to_send_alloc)

        try_to_send_to_chan(c, chan, to_send)
    }
        
    return 
}


cmd_quit :: proc(s: ^Server, c: ^Client, rb: ^Response_Buffer, mess: Message) -> (err: Error) {
    tail := ":QUIT: "
    if len(mess.params) != 0 {
        tail = strings.concatenate(
            {tail, mess.params[0]}, 
            context.temp_allocator,
        )
    }

    to_send_base := Message {
        sender = {full = c.full},
        cmd = "QUIT",
        tail = tail,
    }

    to_send_base.raw = format_message(to_send_base, context.temp_allocator)

    for name in c.chans {
        sync.guard(&s.channs_lock)
        ch := s.channels[name] or_continue

        to_send: Message
        to_send.raw = strings.clone(to_send.raw, ch.to_send_alloc)

        sync.guard(&ch.to_send_lock)
        append(&ch.to_send, to_send)
        
        append(&ch.to_remove, c)
    }

    return rb_cmd_str(rb, s.name, "ERROR", ":Quit")
}


cmd_time :: proc(s: ^Server, c: ^Client, rb: ^Response_Buffer) -> (err: Error) {
    basic :: proc(s: ^Server, c: ^Client, rb: ^Response_Buffer, ts: time.Time) -> (err: Error) {
        ts_buf: [21]u8
        ts_str := strconv.write_int(ts_buf[:], ts._nsec, 10)

        ymd_buf: [32]u8
        ymd := time.to_string_yyyy_mm_dd(ts, ymd_buf[:])
    
        hms_buf: [32]u8
        hms := time.to_string_hms_12(ts, hms_buf[:])
    
        dt_buf: [64]u8 = {0 = ':'}
        p := 1
        p += copy(dt_buf[p:], ymd)
        dt_buf[p] = 'T'
        p += 1
        p += copy(dt_buf[p:], hms)
        dt_buf[p] = 'Z'
        p += 1
        dt_str := string(dt_buf[:p])
    
        return rb_cmd(rb, s.name, .RPL_TIME, c.nick, s.name, ts_str, dt_str)
    }
    
    ts := time.now()

    if s.info.tz == nil {
        return basic(s, c, rb, ts)
    }

    dt, ok := time.time_to_datetime(ts)
    if !ok { 
        return basic(s, c, rb, ts)
    }

    dt, ok = timezone.datetime_to_tz(dt, s.info.tz)
    if !ok {
        return basic(s, c, rb, ts)
    }

    dt_str := timezone.datetime_to_str(dt, context.temp_allocator)

    ts_buf: [21]u8
    ts_str := strconv.write_int(ts_buf[:], ts._nsec, 10)

    return rb_cmd(rb, s.name, .RPL_TIME, c.nick, s.name, ts_str, ":", dt_str)
}


cmd_user :: proc(s: ^Server, c: ^Client, rb: ^Response_Buffer, mess: Message) -> (err: Error) {
    if .Registered in c.flags {
        return rb_cmd(rb, s.name, .ERR_ALREADYREGISTERED, c.nick, ":You may not reregister again")
    }

    if len(mess.params) != 4 && len(mess.params) != 3 {
        return rb_cmd(rb, s.name, .ERR_NEEDMOREPARAMS, "USER :Not enough parameters")
    }

    user := mess.params[0]
    to_lower(user)
    
    real: string
    if len(mess.params) == 4 {
        real = mess.params[3]
    } else if mess.tail != "" {
        real = mess.tail
    }

    if real == "" || user == "" {
        return rb_cmd(rb, s.name, .ERR_NEEDMOREPARAMS, c.nick, "USER :Not enough parameters")
    }

    if !com.is_valid_real(real) {
        return rb_cmd(rb, s.name, .ERR_UNKNOWNERROR, c.nick, "USER :Malformed real name")
    }

    if !com.is_valid_user(user) {
        return rb_cmd(rb, s.name, .ERR_INVALIDUSERNAME, c.nick, "USER :Malformed username")
    }

    if len(user) > s.i_support.user_len {
        idx := trucate_to_grapheme(user, s.i_support.user_len)
        if idx == -1 {
            idx = trucate_to_rune(user, s.i_support.user_len)
            if idx == -1 {
                idx = s.i_support.user_len
            }
        }
        user = user[:idx]
    }

    if len(real) > s.i_support.user_len {
        idx := trucate_to_grapheme(user, s.i_support.user_len)
        if idx == -1 {
            idx = trucate_to_rune(user, s.i_support.user_len)
            if idx == -1 {
                idx = s.i_support.user_len
            }
        }
        real = real[:idx]
    }

    c.user = strings.clone(user)
    c.real = strings.clone(real)
    return
}


cmd_version :: proc(s: ^Server, c: ^Client, rb: ^Response_Buffer) -> (err: Error) {
    rb_cmd(rb, s.name, .RPL_VERSION, s.info.version)
    rb_cmd(rb, s.name, .RPL_ISUPPORT, s.i_support_str)
    
    return 
}


cmd_who :: proc(s: ^Server, c: ^Client, rb: ^Response_Buffer, mess: Message) -> (err: Error) {
    // https://modern.ircdocs.horse/#who-message
    if len(mess.params) <= 0 {
        return rb_cmd(rb, s.name, .RPL_ENDOFWHOIS, c.nick, "* :End of WHO list")
    }

    mask := mess.params[0]

    if mask[0] != '#' {
        u, ok := s.clients[mask]
        if !ok {
            return rb_cmd(rb, s.name, .RPL_ENDOFWHOIS, c.nick, mask, ":End of WHO list")
        }
        return rb_cmd(rb, s.name, .RPL_ENDOFWHOIS, c.nick, mask, u.user, s.name, s.name, c.nick, "", ":0", c.real)
    }

    sync.guard(&s.channs_lock)
    chan, ok := s.channels[mask]
    if !ok {
        return rb_cmd(rb, s.name, .RPL_ENDOFWHOIS, c.nick, mask, ":End of WHO list")
    }

    sync.guard(&s.client_lock)
    sync.guard(&chan.lock)
    for user in chan.users {
        sync.guard(&user.lock)
        if user.user not_in s.clients {
            continue
        }

        rb_cmd(rb, s.name, .RPL_ENDOFWHOIS, c.nick, mask, user.user, s.name, s.name, c.nick, "", ":0", c.real)
    }

    rb_cmd(rb, s.name, .RPL_ENDOFWHOIS, c.nick, mask, ":End of WHO list")

    return 
}


cmd_whois :: proc(s: ^Server, c: ^Client, rb: ^Response_Buffer, mess: Message) -> (err: Error) {
    // https://modern.ircdocs.horse/#whois-message

    if len(mess.params) < 1 {
        return rb_cmd(rb, s.name, .ERR_NONICKNAMEGIVEN, c.nick, ":No nickname given")
    }

    nick := mess.params[len(mess.params)-1]

    name, n_ok := s.nicks[nick]
    if !n_ok {
        return rb_cmd(rb, s.name, .ERR_NOSUCHNICK, c.nick, nick, ":No such nick/channel")
    }

    user, u_ok := s.clients[name]
    if !u_ok {
        return rb_cmd(rb, s.name, .ERR_NOSUCHNICK, c.nick, nick, ":No such nick/channel")
    }

    rb_cmd(
        rb, s.name, .RPL_WHOISUSER, 
        c.nick, nick, name, s.name, 
        strings.concatenate({"* :", user.real}, context.temp_allocator),
    )
    
    info := strings.concatenate({
        ":Server Version " + VERSION,
        ":Server Time", format_server_time(s.info.tz, context.temp_allocator),
        ":Created by blob1807",
        ":Main repo https://github.com/blob1807/basic-irc",
    })

    rb_cmd(rb, s.name, .RPL_WHOISSERVER, c.nick, nick, s.name, info)

    if slice.contains(s.admins[:], name) {
        rb_cmd(rb, s.name, .RPL_WHOISOPERATOR, c.nick, nick, ":is an IRC operator")
    } 

    rb_cmd(rb, s.name, .RPL_ENDOFWHOIS, c.nick, nick, ":End of /WHOIS list")
    return 
}


cmd_cap :: proc(s: ^Server, c: ^Client, rb: ^Response_Buffer, mess: Message, poison: string) -> (done: bool, err: Error) {
    if .Registered in sync.atomic_load(&c.flags) {
        err = rb_cmd(rb, s.name, .ERR_ALREADYREGISTERED, c.nick, "* :You can only negotiate capability once per session")
        done = true
        return
    }

    if len(mess.params) < 1 {
        err = rb_cmd(rb, s.name, .ERR_NEEDMOREPARAMS, c.nick, "CAP :Not enough parameters")
        return
    }

    // Poison the cap list to ensure clients are properaly checking it
    // https://ergo.chat/nope

    switch to_upper(mess.params[0]) {
    case "LS":
        tail := strings.concatenate({":", poison}, context.temp_allocator)
        err = rb_cmd_str(rb, s.name, "CAP", c.nick, "LS", tail)

    case "LIST":
        tail := strings.concatenate({":", poison}, context.temp_allocator)
        err = rb_cmd_str(rb, s.name, "CAP", c.nick, "LIST", tail)

    case "REQ":
        if strings.contains(to_lower(mess.tail), poison) {
            c.quit_mess = strings.concatenate(
                {":Requesting the \"", poison, "\"client capability is forbidden"}, 
                context.temp_allocator,
            )
            c.flags += {.Close}
            return true, IRC_Errors.Capability_Failed
        }

        tail := strings.concatenate({":", mess.tail})
        err = rb_cmd_str(rb, s.name, "CAP", c.nick, "NAK", tail)

    case "END":
        done = true

    case:
        log.error("Invalid capability command", mess.params[0], mess)
        err = rb_cmd(rb, s.name, .ERR_INVALIDCAPCMD, c.nick, "CAP",  mess.params[0], ":Invalid capability command")

    }

    return
}
