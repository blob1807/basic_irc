package basic_irc_server

import "base:runtime"
import ir "base:intrinsics"

import "core:os"
import "core:io"
import "core:net"
import "core:sync"
import "core:time"
import "core:thread"
import "core:time/datetime"
import "core:encoding/json"

import "../common"


TAGS_SIZE         :: 8191
MESSAGE_SIZE      :: 512
MAX_MESSAGE_SIZE  :: TAGS_SIZE + MESSAGE_SIZE

NET_READ_SIZE   :: 512
NET_BUFFER_SIZE :: MAX_MESSAGE_SIZE + NET_READ_SIZE

NET_RECEV_TIMEOUT    :: time.Millisecond * 1000
CLIENT_CHECK_TIMEOUT :: time.Millisecond * 50
ONBOARD_TIMEOUT      :: time.Second * 30

SERVER_THREAD_TIMEOUT  :: time.Millisecond * 10
CLIENT_THREAD_TIMEOUT  :: time.Millisecond * 50
CHANNEL_THREAD_TIMEOUT :: time.Millisecond * 50


@(rodata)
MESS_END      := []byte{'\r', '\n'}
MESS_END_STR  :: "\r\n"

//  i: invisable; o: global OP;
USER_MODES    :: "+io"

// +l: user limit; +n: no external messages;
CHANNEL_MODES :: "+ln" 

DEFAULT_ADDRESS :: "127.0.0.1:69"
DEFAULT_NAME    :: "heimdall"
DEFAULT_NETWORK :: "Bifröst"

VERSION :: "Hermóðr"

DEFAULT_ENDPOINT := net.Endpoint {
    address = net.IP4_Loopback,
    port = 6667,
}


// 10 mins between checks
PING_TIMER_DURATION       :: time.Minute * 8
PING_CHECK_TIMER_DURATION :: time.Minute * 2
CLIENT_CLEANUP_TIMER_DURATION :: time.Millisecond * 500


DEFAULT_I_SUPPORT :: I_Support {
    case_map    = "ascii",
    chan_limit  = {'#', -1},
    chan_modes  = {'l', 'n'},
    chan_types  = "#",
    max_targets = 5,
    network     = DEFAULT_NETWORK,
    nick_len    = 8,
    status_msg  = "@+",
    user_len    = 16,
}

// TODO: Apprently it's malformed formating
DEFAULT_I_SUPPORT_STR :: "CASEMAPPING=ascii CHANLIMIT=#: CHANMODES=l,n CHANTYPES=# MAXTARGETS=5 NETWORK=" + DEFAULT_NETWORK + " NICKLEN=8 STATUSMSG=@+ USERLEN=16"


IRC_Errors :: enum { 
    Invalid_Rune_Found, 

    Unable_To_Find_Channel, 
    No_Valid_Channel_Found, 
    Not_In_Channel, 
    Hit_Channel_Limit,
    Already_In_Channel,

    Buffer_Full, 
    No_End_Of_Message, 
    No_Message_To_Send, 

    Message_To_Big, 
    Sent_More_Data_Then_Given, 
    Failed_To_Send_Message, 

    Join_Server_Fail,

    Cmd_Error,
    User_Mess_To_Big,

    Config_Error,
    Registration_Failed,
    Capability_Failed,

    Server_Force_Quit,
}

Error :: union #shared_nil { 
    runtime.Allocator_Error, 
    net.Network_Error, 
    os.Error,
    io.Error,
    json.Unmarshal_Error,

    IRC_Errors, 
}



Response_Buffer :: struct {
    sock: net.TCP_Socket,
    data: [dynamic]u8 `fmt:"q"`,
}


Net_Buffer :: struct {
    buf:  [NET_BUFFER_SIZE]byte `fmt:"q,pos"`,
    pos:  int, // amount writen
    read: int, // amount read
}


Timer :: struct {
    duration: time.Duration,
    left: time.Duration,
    last: time.Tick,
}


Thread_Flag :: enum {
    Has_Closed, Closeing,
}

Thread_Flags :: bit_set[Thread_Flag]


Server_Flag :: enum {
    Pinging,
}

Server_Flags :: bit_set[Server_Flag]



Server :: struct {
    name: string,
    
    address: string,
    sock: net.TCP_Socket,
    ep:   net.Endpoint,

    net_buf: Net_Buffer,

    base_alloc: runtime.Allocator,
    base_logger: runtime.Logger,

    nicks:    map[string]string,  //     nick -> username
    clients:  map[string]^Client, // username -> Client
    nick_lock:   sync.Ticket_Mutex,
    client_lock: sync.Ticket_Mutex,
    
    channels: map[string]^Channel,
    channs_lock: sync.Ticket_Mutex, 

    close_client_threads:    bool, // atmoic
    close_channel_threads:   bool, // atmoic
    close_new_client_thread: bool, // atmoic
    close_server: bool,  // atmoic

    flags: Server_Flags, // atmoic
    // caps:  common.Capabilities_Set,

    using i_support: I_Support,
    i_support_str: string,

    stats: Server_Stats,
    info:  Server_Info,

    admins: [dynamic]string, // usernames

    onboard_timeout: time.Duration,
    
    timers: struct {
        ping, ping_check: Timer,
        client_cleanup:   Timer,
    },
}


Server_Stats :: struct {
    max_num_clients: int,
}


Server_Info :: struct {
    created: time.Time,
    tz: ^datetime.TZ_Region,
    version: string,
}



Client_Flag :: enum {
    Close, Pinged, Ping_Failed, Invisable, Op, Errored,
    Quit, Registered,
}

Client_Flags :: bit_set[Client_Flag]

Client :: struct {
    nick: string `fmt:"q"`,
    user: string `fmt:"q"`, 
    real: string `fmt:"q"`,
    full: string `fmt:"q"`,

    sock: net.TCP_Socket,
    ep:   net.Endpoint, 

    net_buf: Net_Buffer,
    
    flags: Client_Flags, // atmoic
    caps: common.Capabilities_Set,

    ping_token: string `fmt:"q"`,
    pinged: time.Tick,

    chans:   [dynamic]string,
    to_send: [dynamic]Message, 
    to_send_lock: sync.Mutex,

    // Messages WILL have their `raw` field allocated to the dest's allocator
    mess_cache: [dynamic]Cached_Message,

    to_send_alloc: runtime.Allocator,

    thread: ^thread.Thread,
    thread_flags: Thread_Flags, // atomic
    lock: sync.Mutex,

    quit_mess: string `fmt:"q"`,

    cleanup_check_count: int,
}


Channel_Flag :: enum {
    Close, 
}

Channel_Flags :: bit_set[Channel_Flag]

Channel_Mode :: enum {
    Ban, Exception, Client_Limit, 
    Invite_Only, Invite_Exception, 
    Key, Moderated, Secret, 
    Protected_Topic, No_Exteral_Messages,
}

Channel_Modes :: bit_set[Channel_Mode]

Channel :: struct {
    name:  string,
    admin: [dynamic]string,  // usernames
    users: [dynamic]^Client,

    to_remove: [dynamic]^Client, 
    to_send:   [dynamic]Message, 
    to_send_lock: sync.Mutex,

    to_send_alloc: runtime.Allocator,

    flags: Channel_Flags, // atmoic

    modes: Channel_Modes,
    user_limit: int,

    thread: ^thread.Thread,
    thread_flags: Thread_Flags, // atomic
    lock: sync.Mutex,
}


Sender_Type :: enum {
    None, Invalid, Server, Self, User, Sys, Sys_Err,
}

Sender :: struct {
    full: string `fmt:"q"`,
    name: string `fmt:"q"`,
    type: Sender_Type,
}

Message :: struct {
    recived: time.Time,
    raw:     string `fmt:"q"`, // All other fields are views/slices into this string.
    tags:    string `fmt:"q"`,
    sender:  Sender,
    cmd:     string `fmt:"q"`,
    code:    common.Response_Code,
    params:  []string,
    tail:    string `fmt:"q"`,
}


Cached_Message :: struct {
    using mess: Message,
    dest:  string `fmt:"q"`,
    delay: Timer,
}


I_Support :: struct {
    case_map:   string, // only "ascii"

    chan_limit: struct{mode: byte, limit: int}, // only set "#"
    chan_modes: [2]byte, // see CHANNEL_MODES
    chan_types: string,  // only "#"

    max_targets: int,

    network:  string,
    nick_len: int,

    status_msg: string, // only "@" & "+"
    user_len:   int,
}


Config :: struct {
    name:    string,
    address: string,
    admins:  []string,

    // caps_set: common.Capabilities_Set,
    // caps_arr: []common.Capability,

    timeouts: struct {
        onboard: time.Duration,
    },

    timers: struct {
        ping:           time.Duration,
        ping_check:     time.Duration,
        client_cleanup: time.Duration,
    },

    i_support: I_Support,
}

