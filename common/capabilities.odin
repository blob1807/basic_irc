package basic_irc_common

import "base:runtime"

import "core:math/rand"

// https://ircv3.net/registry#Capability

CAPS     :: Capability
CAP_SET  :: Capabilities_Set
CAPS_STR := Capability_Strings


Capability :: enum {
    Invalid = 0,

    Account_Notify,
    Account_Registration, // draft
    Account_Tag,
    Away_Notify,
    Batch,
    Cap_Notify,
    Channel_Rename,       // draft
    Chathistory,          // draft
    Chghost,
    Echo_Message,
    Event_Playback,       // draft
    Extended_Join,
    Extended_Monitor,
    Invite_Notify,
    Labeled_Response,
    Message_Redaction,    // draft
    Message_Tags,
    Metadata_2,           // draft
    Monitor,
    Multi_Prefix,
    Multiline,            // draft
    No_Implicit_names,    // draft
    Pre_Away,             // draft
    Read_Marker,          // draft
    SASL,
    Server_Time,
    Setname,
    Standard_Replies,
    TLS,               // deprecated
    Userhost_in_Names,
}

Capabilities_Set :: bit_set[Capability]

@(rodata)
Capability_Versions := [?]int {
    302, 
}


@(rodata)
Capability_Strings := [len(Capability)]string {
    "",
    "account-notify",
    "account-registration",
    "account-tag",
    "away-notify",
    "batch",
    "cap-notify",
    "channel-rename",
    "chathistory",
    "chghost",
    "echo-message",
    "event-playback",
    "extended-join",
    "extended-monitor",
    "invite-notify",
    "labeled-response",
    "message-redaction",
    "message-tags",
    "metadata-2",
    "monitor",
    "multi-prefix",
    "multiline",
    "no-implicit-names",
    "pre-away",
    "read-marker",
    "sasl",
    "server-time",
    "setname",
    "standard-replies",
    "tls",
    "userhost-in-names",
}


@(rodata)
Capability_to_String_Array := [Capability]string {
    .Invalid                = "",
  
    .Account_Notify         = "account-notify",
    .Account_Registration   = "account-registration",
    .Account_Tag            = "account-tag",
    .Away_Notify            = "away-notify",
    .Batch                  = "batch",
    .Cap_Notify             = "cap-notify",
    .Channel_Rename         = "channel-rename",
    .Chathistory            = "chathistory",
    .Chghost                = "chghost",
    .Echo_Message           = "echo-message",
    .Event_Playback         = "event-playback",
    .Extended_Join          = "extended-join",
    .Extended_Monitor       = "extended-monitor",
    .Invite_Notify          = "invite-notify",
    .Labeled_Response       = "labeled-response",
    .Message_Redaction      = "message-redaction",
    .Message_Tags           = "message-tags",
    .Metadata_2             = "metadata-2",
    .Monitor                = "monitor",
    .Multi_Prefix           = "multi-prefix",
    .Multiline              = "multiline",
    .No_Implicit_names      = "no-implicit-names",
    .Pre_Away               = "pre-away",
    .Read_Marker            = "read-marker",
    .SASL                   = "sasl",
    .Server_Time            = "server-time",
    .Setname                = "setname",
    .Standard_Replies       = "standard-replies",
    .TLS                    = "tls",
    .Userhost_in_Names      = "userhost-in-names",
}


/*
String_to_Capability_Map  := map[string]Capability {
    ""                     = .Invalid,
    "account-notify"       = .Account_Notify,
    "account-registration" = .Account_Registration,
    "account-tag"          = .Account_Tag,
    "away-notify"          = .Away_Notify,
    "batch"                = .Batch,
    "cap-notify"           = .Cap_Notify,
    "channel-rename"       = .Channel_Rename,
    "chathistory"          = .Chathistory,
    "chghost"              = .Chghost,
    "echo-message"         = .Echo_Message,
    "event-playback"       = .Event_Playback,
    "extended-join"        = .Extended_Join,
    "extended-monitor"     = .Extended_Monitor,
    "invite-notify"        = .Invite_Notify,
    "labeled-response"     = .Labeled_Response,
    "message-redaction"    = .Message_Redaction,
    "message-tags"         = .Message_Tags,
    "metadata-2"           = .Metadata_2,
    "monitor"              = .Monitor,
    "multi-prefix"         = .Multi_Prefix,
    "multiline"            = .Multiline,
    "no-implicit-names"    = .No_Implicit_names,
    "pre-away"             = .Pre_Away,
    "read-marker"          = .Read_Marker,
    "sasl"                 = .SASL,
    "server-time"          = .Server_Time,
    "setname"              = .Setname,
    "standard-replies"     = .Standard_Replies,
    "tls"                  = .TLS,
    "userhost-in-names"    = .Userhost_in_Names,
}
*/

String_to_Capability_Map: map[string]Capability


cap_to_string :: proc(c: Capability) -> (res: string, ok: bool) {
    if c < min(Capability) || c > max(Capability) {
        return 
    }
    return Capability_to_String_Array[c], true
}


string_to_cap :: proc(str: string) -> (res: Capability, ok: bool) {
    return String_to_Capability_Map[str]
}


// Invalid Capabilities are ignored
caps_to_set :: proc(cs: []Capability) -> (res: Capabilities_Set) {
    for c in cs {
        if c < min(Capability) || c > max(Capability) {
            continue 
        }
        res += {c}
    }
    return
}


// Invalid Capabilities are ignored
caps_str_to_set :: proc(cs: []string) -> (res: Capabilities_Set) {
    for str in cs {
        c := string_to_cap(str) or_continue
        res += {c}
    }
    return
}


set_to_caps :: proc(set: Capabilities_Set, alloc: runtime.Allocator) -> (res: []Capability, err: runtime.Allocator_Error) {
    res = make([]Capability, card(set), alloc) or_return
    pos: int

    for c in set {
        res[pos] = c
        pos += 1
    }

    return
}


set_to_caps_str :: proc(set: Capabilities_Set, alloc: runtime.Allocator, poison := "") -> (res: []string, err: runtime.Allocator_Error) {
    size := card(set) + (poison == "" ? 0 : 1)
    buf := make([dynamic]string, 0, size, alloc) or_return
    defer if err != nil {
        delete(buf)
    }

    for c in set {
        str := cap_to_string(c) or_continue
        append(&buf, str) or_return
    }

    if poison != "" {
        inject_at_elems(&buf, rand.int_max(len(buf)-1), poison) or_return
    }

    shrink(&buf)
    return buf[:], nil
}


@(fini)
comm_cleanup :: proc() {
    delete(String_to_Capability_Map)
}



//@(private)
@(init)
comm_init :: proc() {
    String_to_Capability_Map = make(map[string]Capability, len(Capability))
    m := String_to_Capability_Map
    m[""]                     = .Invalid
    m["account-notify"]       = .Account_Notify
    m["account-registration"] = .Account_Registration
    m["account-tag"]          = .Account_Tag
    m["away-notify"]          = .Away_Notify
    m["batch"]                = .Batch
    m["cap-notify"]           = .Cap_Notify
    m["channel-rename"]       = .Channel_Rename
    m["chathistory"]          = .Chathistory
    m["chghost"]              = .Chghost
    m["echo-message"]         = .Echo_Message
    m["event-playback"]       = .Event_Playback
    m["extended-join"]        = .Extended_Join
    m["extended-monitor"]     = .Extended_Monitor
    m["invite-notify"]        = .Invite_Notify
    m["labeled-response"]     = .Labeled_Response
    m["message-redaction"]    = .Message_Redaction
    m["message-tags"]         = .Message_Tags
    m["metadata-2"]           = .Metadata_2
    m["monitor"]              = .Monitor
    m["multi-prefix"]         = .Multi_Prefix
    m["multiline"]            = .Multiline
    m["no-implicit-names"]    = .No_Implicit_names
    m["pre-away"]             = .Pre_Away
    m["read-marker"]          = .Read_Marker
    m["sasl"]                 = .SASL
    m["server-time"]          = .Server_Time
    m["setname"]              = .Setname
    m["standard-replies"]     = .Standard_Replies
    m["tls"]                  = .TLS
    m["userhost-in-names"]    = .Userhost_in_Names
}
