package basic_irc_server

import "base:runtime"

import "core:mem"
import "core:net"
import "core:time"
import "core:thread"
import "core:strings"
import "core:reflect"
import "core:time/timezone"
import "core:time/datetime"
import "core:encoding/json"

import com "../common"


set_ctrl_hander :: proc() -> bool {
    return _set_ctrl_hander()
}


format_i_support :: proc(i: I_Support, alloc := context.allocator) -> (res: string, err: runtime.Allocator_Error) {
    // TODO: Apprently it's making malformed formating
    // Probaly missing things
    s :: strings
    sb := s.builder_make(alloc) or_return

    s.write_string(&sb, "CASEMAPPING=")
    s.write_string(&sb, i.case_map)

    s.write_string(&sb, " CHANLIMIT=")
    s.write_bytes(&sb, {i.chan_limit.mode, ':'})
    if i.chan_limit.limit != -1 {
        s.write_int(&sb, i.chan_limit.limit)
    }

    //Doesn't separate mode types.
    s.write_string(&sb, " CHANMODES=")
    s.write_bytes(&sb, {',',',',i.chan_modes[0],',',i.chan_modes[1]})

    s.write_string(&sb, " CHANTYPES=")
    s.write_string(&sb, i.chan_types)

    s.write_string(&sb, " MAXTARGETS=")
    s.write_int(&sb, i.max_targets, 10)

    s.write_string(&sb, " NETWORK=")
    s.write_string(&sb, i.network)

    s.write_string(&sb, " NICKLEN=")
    s.write_int(&sb, i.nick_len, 10)

    s.write_string(&sb, " STATUSMSG=")
    s.write_string(&sb, i.status_msg)

    s.write_string(&sb, " USERLEN=")
    s.write_int(&sb, i.user_len, 10)
    
    res = strings.to_string(sb)
    return 
}


// takes a json file as a `[]u8` & write the config to a `^Server`. 
// setting default for anything unset.
load_config :: proc(buf: []u8, s: ^Server, alloc := context.allocator) -> (err: Error) {
    context.allocator = alloc

    c: Config
    json.unmarshal_any(buf, &c) or_return
    i := &c.i_support
    d := DEFAULT_I_SUPPORT

    if i.case_map == "" {
        i.case_map = strings.clone(d.case_map)

    } else if !com.is_equal(i.case_map, "ascii") {
        return IRC_Errors.Config_Error

    } else {
        to_lower(i.case_map)
    }

    if i.chan_limit == {} {
        i.chan_limit = d.chan_limit

    } else if i.chan_limit.mode != '#' || i.chan_limit.limit < 0 {
        return IRC_Errors.Config_Error
    }

    if i.chan_modes == {} {
        i.chan_modes = d.chan_modes

    } else if i.chan_modes != {'l', 'n'} || i.chan_modes != {'n', 'l'} {
        return IRC_Errors.Config_Error
    }

    if i.chan_types == "" {
        i.chan_types = strings.clone(d.chan_types)

    } else if i.chan_types != "#" {
        return IRC_Errors.Config_Error
    
    }

    if i.max_targets == 0 {
        i.max_targets = d.max_targets
    }

    if i.network == "" {
        i.network = strings.clone(d.network)
    }

    if i.nick_len == 0 {
        i.nick_len = d.nick_len
    }

    if i.status_msg == "" {
        i.status_msg = strings.clone(d.status_msg)
    
    } else if i.status_msg != "@+" || i.status_msg != "+@" {
        return IRC_Errors.Config_Error
    }

    if i.user_len == 0 {
        i.user_len = d.user_len
    }


    if c.name == "" {
        c.name = strings.clone(DEFAULT_NAME)
    }
    if c.address == "" {
        c.address = strings.clone(DEFAULT_ADDRESS)
    }

    if c.timeouts.onboard == 0 {
        c.timeouts.onboard = ONBOARD_TIMEOUT
    }

    if c.timers.ping == 0 {
        c.timers.ping = PING_TIMER_DURATION
    }
    if c.timers.ping_check == 0 {
        c.timers.ping_check = PING_CHECK_TIMER_DURATION
    }
    if c.timers.client_cleanup == 0 {
        c.timers.client_cleanup = CLIENT_CLEANUP_TIMER_DURATION
    }

    /*
    if c.caps_arr != nil {
        c.caps_set = com.caps_to_set(c.caps_arr)
        delete(c.caps_arr)
    }
    */


    s.name = c.name
    s.address = c.address
    s.i_support = c.i_support
    s.i_support_str = format_i_support(c.i_support) or_return

    s.onboard_timeout = c.timeouts.onboard
    s.timers.ping.duration = c.timers.ping
    s.timers.ping_check.duration = c.timers.ping_check

    // s.caps = c.caps_set


    if len(c.admins) != 0 {
        append(&s.admins, ..c.admins) or_return 
        delete(c.admins)
    }
    
    return 
}


tick_timers :: proc "contextless" (trs: []Timer) {
    c := time.tick_now()
    for &t in trs {
        t.left -= time.tick_diff(t.last, c)
        t.last = c
    }
}

update_timer :: proc "contextless" (t: ^Timer) -> bool {
    c := time.tick_now()
    t.left -= time.tick_diff(t.last, c)
    t.last = c
    return t.left <= 0
}

reset_timer :: start_timer

start_timer :: proc "contextless" (t: ^Timer) {
    t.left = t.duration
    t.last = time.tick_now()
}

stop_timer :: proc "contextless" (t: ^Timer) {
    t.left = 0
}

timer_ended :: proc "contextless" (t: Timer) -> bool {
    return t.left <= 0
}


// WARNING: MODIFIES INPUT STRING!!! Used for nick & usernames
to_lower :: proc "contextless" (str: string) -> string {
    // TODO: If I care about speed, look up table might be better
    buf := transmute([]u8)str

    for &b in buf {
        if 'A' <= b && b <= 'Z' {
            b |= 32
        }
    }

    return str
}

// WARNING: MODIFIES INPUT STRING!!! Used for message commmnds
to_upper :: proc "contextless" (str: string) -> string {
    // TODO: If I care about speed, look up table might be better
    buf := transmute([]u8)str

    for &b in buf {
        if 'a' <= b && b <= 'z' {
            b &~= 32
        }
    }

    return str
}


format_server_time :: proc(tz: ^datetime.TZ_Region, alloc: runtime.Allocator) -> string {
    basic :: proc(ts: time.Time) -> string {
        ymd_buf: [32]u8
        ymd := time.to_string_yyyy_mm_dd(ts, ymd_buf[:])
    
        hms_buf: [32]u8
        hms := time.to_string_hms_12(ts, ymd_buf[:])
    
        dt_buf: [64]u8
        p := copy(dt_buf[:], ymd)
        dt_buf[p] = 'T'
        p += 1
        p += copy(dt_buf[p:], hms)
        dt_buf[p] = 'Z'
        p += 1
        dt_str := string(dt_buf[:p])
    
        return strings.concatenate({ymd, hms, dt_str})
    }
    context.allocator = alloc
    
    ts := time.now()

    if tz == nil {
        return basic(ts)
    }

    dt, ok := time.time_to_datetime(ts)
    if !ok { 
        return basic(ts)
    }

    dt, ok = timezone.datetime_to_tz(dt, tz)
    if !ok {
        return basic(ts)
    }

    return timezone.datetime_to_str(dt)
}


destroy_message :: proc(mess: Message, alloc := context.allocator) {
    context.allocator = alloc
    delete(mess.raw)
    delete(mess.params)
}


destroy_i_support :: proc(s: ^Server, alloc := context.allocator) {
    context.allocator = alloc
    delete(s.i_support_str)
    delete(s.i_support.case_map)
    delete(s.i_support.chan_types)
    delete(s.i_support.network)
    delete(s.i_support.status_msg)
}


destroy_user :: proc(c: ^Client, alloc := context.allocator) {
    context.allocator = alloc
    if c.thread != nil {
        thread.terminate(c.thread, 0)
        thread.destroy(c.thread)
    }

    if c.sock != 0 {
        net.close(c.sock)
    }

    delete(c.full)
    delete(c.nick)
    delete(c.user)
    delete(c.real)
    delete(c.chans)
    delete(c.ping_token)
    
    mem.zero(c, size_of(Client))
}


destroy_chan :: proc(c: ^Channel, alloc := context.allocator) {
    context.allocator = alloc
    if c.thread != nil {
        thread.terminate(c.thread, 0)
        thread.destroy(c.thread)
    }

    delete(c.name)
    delete(c.admin)
    delete(c.users)

    mem.zero(c, size_of(Channel))
}

