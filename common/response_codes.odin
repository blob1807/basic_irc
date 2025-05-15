package basic_irc_common

RC :: Response_Codes

// https://www.alien.net.au/irc/irc2numerics.html

Response_Codes :: enum {
    None = 0,
    
    // 1 to 99 client-server connections only
    RPL_WELCOME  = 1,
    RPL_YOURHOST = 2,
    RPL_CREATED  = 3,
    RPL_MYINFO   = 4,
    RPL_ISUPPORT = 5,
    RPL_BOUNCE   = 10,

    // 200 to 399 all connections
    RPL_STATSLINKINFO = 211,
    RPL_STATSCOMMANDS = 212,
    RPL_STATSCLINE    = 213,
    RPL_STATSILINE    = 215,
    RPL_STATSKLINE    = 216,
    RPL_ENDOFSTATS    = 219,
    RPL_UMODEIS       = 221,
    RPL_STATSLLINE    = 241,
    RPL_STATSUPTIME   = 242,
    RPL_STATSOLINE    = 243,
    RPL_STATSHLINE    = 244,
    RPL_LUSERCLIENT   = 251,
    RPL_LUSEROP       = 252,
    RPL_LUSERUNKNOWN  = 253,
    RPL_LUSERCHANNELS = 254,
    RPL_LUSERME       = 255,
    RPL_ADMINME       = 256,
    RPL_ADMINLOC1     = 257,
    RPL_ADMINLOC2     = 258,
    RPL_ADMINEMAIL    = 259,
    RPL_TRYAGAIN      = 263,
    RPL_LOCALUSERS    = 265,
    RPL_GLOBALUSERS   = 266,
    RPL_WHOISCERTFP   = 276,

    RPL_NONE = 300,
    RPL_AWAY, 
    RPL_USERHOST,
    RPL_UNAWAY = 305,
    RPL_NOWAWAY,
    RPL_WHOISREGNICK,
    RPL_WHOISUSER = 311,
    RPL_WHOISSERVER,
    RPL_WHOISOPERATOR,
    RPL_WHOWASUSER,
    RPL_ENDOFWHO,
    RPL_WHOISIDLE = 317,
    RPL_ENDOFWHOIS,
    RPL_WHOISCHANNELS,
    RPL_WHOISSPECIAL,
    RPL_LISTSTART,
    RPL_LIST,
    RPL_LISTEND,
    RPL_CHANNELMODEIS,
    RPL_CREATIONTIME = 329,
    RPL_WHOISACCOUNT,
    RPL_NOTOPIC,
    RPL_TOPIC,
    RPL_TOPICWHOTIME,
    RPL_INVITELIST = 336, // 'INVITE' COMMAND. Some use 346 because of RFC2812.
    RPL_ENDOFINVITELIST,  // 'INVITE' COMMAND. Some use 347 because of RFC2812.
    RPL_WHOISACTUALLY,
    RPL_INVITING = 341,
    RPL_INVEXLIST = 346, // 'MODE' COMMAND. Sometimes is RPL_INVITELIST because of RFC2812.
    RPL_ENDOFINVEXLIST,  // 'MODE' COMMAND. Sometimes is RPL_ENDOFINVITELIST because of RFC2812.
    RPL_EXCEPTLIST,
    RPL_ENDOFEXCEPTLIST,
    RPL_VERSION = 351,
    RPL_WHOREPLY,
    RPL_NAMREPLY,
    RPL_LINKS = 364,
    RPL_ENDOFLINKS,
    RPL_ENDOFNAMES,
    RPL_BANLIST,
    RPL_ENDOFBANLIST,
    RPL_ENDOFWHOWAS,
    RPL_INFO = 371,
    RPL_MOTD,
    RPL_ENDOFINFO = 374,
    RPL_MOTDSTART,
    RPL_ENDOFMOTD,
    RPL_WHOISHOST = 378,
    RPL_WHOISMODES,
    RPL_YOUREOPER = 381,
    RPL_REHASHING,
    RPL_TIME = 391,

    // Other RPL
    RPL_STARTTLS = 670,
    RPL_WHOISSECURE,

    RPL_HELPSTART = 704,
    RPL_HELPTXT,
    RPL_ENDOFHELP,

    RPL_LOGGEDIN = 900,
    RPL_LOGGEDOUT,
    RPL_SASLSUCCESS = 903,
    RPL_SASLMECHS = 908,

    // Errors
    ERR_UNKNOWNERROR = 400,
    ERR_NOSUCHNICK,
    ERR_NOSUCHSERVER,
    ERR_NOSUCHCHANNEL,
    ERR_CANNOTSENDTOCHAN,
    ERR_TOOMANYCHANNELS,
    ERR_WASNOSUCHNICK,
    ERR_TOOMANYTARGETS,
    ERR_NOORIGIN = 409,
    ERR_NORECIPIENT = 411,
    ERR_NOTEXTTOSEND,
    ERR_NOTOPLEVEL,
    ERR_WILDTOPLEVEL,
    ERR_INPUTTOOLONG = 417,
    ERR_UNKNOWNCOMMAND = 421,
    ERR_NOMOTD,
    ERR_NONICKNAMEGIVEN = 431,
    ERR_ERRONEUSNICKNAME,
    ERR_NICKNAMEINUSE,
    ERR_NICKCOLLISION = 436,
    ERR_USERNOTINCHANNEL = 441,
    ERR_NOTONCHANNEL,
    ERR_USERONCHANNEL,
    ERR_NOTREGISTERED = 451,
    ERR_NEEDMOREPARAMS = 461,
    ERR_ALREADYREGISTERED,
    ERR_PASSWDMISMATCH = 464,
    ERR_YOUREBANNEDCREEP,
    ERR_CHANNELISFULL = 471,
    ERR_UNKNOWNMODE,
    ERR_INVITEONLYCHAN,
    ERR_BANNEDFROMCHAN,
    ERR_BADCHANNELKEY,
    ERR_BADCHANMASK,
    ERR_NOPRIVILEGES = 481,
    ERR_CHANOPRIVSNEEDED,
    ERR_CANTKILLSERVER,
    ERR_NOOPERHOST = 491,

    ERR_UMODEUNKNOWNFLAG = 501,
    ERR_USERSDONTMATCH,
    ERR_HELPNOTFOUND = 524,
    ERR_INVALIDKEY,

    ERR_STARTTLS = 691,
    ERR_INVALIDMODEPARAM = 696,

    ERR_NOPRIVS = 723,

    ERR_NICKLOCKED = 902,
    ERR_SASLFAIL = 904,
    ERR_SASLTOOLONG,
    ERR_SASLABORTED, 
    ERR_SASLALREADY,
}


// Inclusive Ranges
@(rodata)
RPL_RANGES := [?]struct {s, e: Response_Codes} {
    {  RC(1),  RC(99)}, {RC(200), RC(399)},
    {RC(670), RC(671)}, {RC(704), RC(706)},
    {RC(900), RC(901)}, {RC(903), RC(903)}, 
    {RC(908), RC(908)}, 
} 

// Inclusive Ranges
@(rodata)
ERR_RANGES := [?]struct {s, e: Response_Codes} {
    {RC(400), RC(491)}, {RC(501), RC(502)}, 
    {RC(524), RC(525)}, {RC(691), RC(691)}, 
    {RC(696), RC(696)}, {RC(723), RC(723)}, 
    {RC(902), RC(902)}, {RC(904), RC(907)}, 
}

is_reply_code :: proc(code: Response_Codes) -> bool {
    for r in RPL_RANGES {
        if r.s <= code && code <= r.e {
            return true
        }
    }
    return false
}

is_error_code :: proc(code: Response_Codes) -> bool {
    for r in ERR_RANGES {
        if r.s <= code && code <= r.e {
            return true
        }
    }
    return false
}

is_valid_code :: proc(code: Response_Codes) -> bool {
    return is_reply_code(code) || is_error_code(code)
}


@private
is_valid_code_table :: proc(code: Response_Codes) -> bool {
    return Valid_Response_Codes[code]
}


@(private, rodata)
Valid_Response_Codes: #sparse [Response_Codes]bool

