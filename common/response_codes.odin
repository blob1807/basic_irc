package basic_irc_common

RC :: Response_Code

// https://www.alien.net.au/irc/irc2numerics.html

Response_Code :: enum {
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

	RPL_NONE            = 300,
	RPL_AWAY            = 301, 
	RPL_USERHOST        = 302,
	RPL_UNAWAY          = 305,
	RPL_NOWAWAY         = 306,
	RPL_WHOISREGNICK    = 307,
	RPL_WHOISUSER       = 311,
	RPL_WHOISSERVER     = 312,
	RPL_WHOISOPERATOR   = 313,
	RPL_WHOWASUSER      = 314,
	RPL_ENDOFWHO        = 315,
	RPL_WHOISIDLE       = 317,
	RPL_ENDOFWHOIS      = 318,
	RPL_WHOISCHANNELS   = 319,
	RPL_WHOISSPECIAL    = 320,
	RPL_LISTSTART       = 321,
	RPL_LIST            = 322,
	RPL_LISTEND         = 323,
	RPL_CHANNELMODEIS   = 324,
	RPL_CREATIONTIME    = 329,
	RPL_WHOISACCOUNT    = 330,
	RPL_NOTOPIC         = 331,
	RPL_TOPIC           = 332,
	RPL_TOPICWHOTIME    = 333,
	RPL_INVITELIST      = 336, // 'INVITE' COMMAND. Some use 346 because of RFC2812.
	RPL_ENDOFINVITELIST = 337, // 'INVITE' COMMAND. Some use 347 because of RFC2812.
	RPL_WHOISACTUALLY   = 338,
	RPL_INVITING        = 341,
	RPL_INVEXLIST       = 346, // 'MODE' COMMAND. Sometimes is RPL_INVITELIST because of RFC2812.
	RPL_ENDOFINVEXLIST  = 347, // 'MODE' COMMAND. Sometimes is RPL_ENDOFINVITELIST because of RFC2812.
	RPL_EXCEPTLIST      = 348,
	RPL_ENDOFEXCEPTLIST = 349,
	RPL_VERSION         = 351,
	RPL_WHOREPLY        = 352,
	RPL_NAMREPLY        = 353,
	RPL_LINKS           = 364,
	RPL_ENDOFLINKS      = 365,
	RPL_ENDOFNAMES      = 366,
	RPL_BANLIST         = 367,
	RPL_ENDOFBANLIST    = 368,
	RPL_ENDOFWHOWAS     = 369,
	RPL_INFO            = 371,
	RPL_MOTD            = 372,
	RPL_ENDOFINFO       = 374,
	RPL_MOTDSTART       = 375,
	RPL_ENDOFMOTD       = 376,
	RPL_WHOISHOST       = 378,
	RPL_WHOISMODES      = 379,
	RPL_YOUREOPER       = 381,
	RPL_REHASHING       = 382,
	RPL_TIME            = 391,

	// Other RPL
	RPL_STARTTLS    = 670,
	RPL_WHOISSECURE = 671,

	RPL_HELPSTART = 704,
	RPL_HELPTXT   = 705,
	RPL_ENDOFHELP = 706,

	RPL_LOGGEDIN    = 900,
	RPL_LOGGEDOUT   = 901,
	RPL_SASLSUCCESS = 903,
	RPL_SASLMECHS   = 908,

	// Errors
	ERR_UNKNOWNERROR      = 400,
	ERR_NOSUCHNICK        = 401,
	ERR_NOSUCHSERVER      = 402,
	ERR_NOSUCHCHANNEL     = 403,
	ERR_CANNOTSENDTOCHAN  = 404,
	ERR_TOOMANYCHANNELS   = 405,
	ERR_WASNOSUCHNICK     = 406,
	ERR_TOOMANYTARGETS    = 407,
	ERR_NOORIGIN          = 409,
	ERR_NORECIPIENT       = 411,
	ERR_NOTEXTTOSEND      = 412,
	ERR_NOTOPLEVEL        = 413,
	ERR_WILDTOPLEVEL      = 414,
	ERR_INPUTTOOLONG      = 417,
	ERR_UNKNOWNCOMMAND    = 421,
	ERR_NOMOTD            = 422,
	ERR_NONICKNAMEGIVEN   = 431,
	ERR_ERRONEUSNICKNAME  = 432,
	ERR_NICKNAMEINUSE     = 433,
	ERR_NICKCOLLISION     = 436,
	ERR_USERNOTINCHANNEL  = 441,
	ERR_NOTONCHANNEL      = 442,
	ERR_USERONCHANNEL     = 443,
	ERR_NOTREGISTERED     = 451,
	ERR_NEEDMOREPARAMS    = 461,
	ERR_ALREADYREGISTERED = 462,
	ERR_PASSWDMISMATCH    = 464,
	ERR_YOUREBANNEDCREEP  = 465,
	ERR_INVALIDUSERNAME   = 468,
	ERR_CHANNELISFULL     = 471,
	ERR_UNKNOWNMODE       = 472,
	ERR_INVITEONLYCHAN    = 473,
	ERR_BANNEDFROMCHAN    = 474,
	ERR_BADCHANNELKEY     = 475,
	ERR_BADCHANMASK       = 476,
	ERR_NOPRIVILEGES      = 481,
	ERR_CHANOPRIVSNEEDED  = 482,
	ERR_CANTKILLSERVER    = 483,
	ERR_NOOPERHOST        = 491,

	ERR_UMODEUNKNOWNFLAG = 501,
	ERR_USERSDONTMATCH   = 502,
	ERR_HELPNOTFOUND     = 524,
	ERR_INVALIDKEY       = 525,

	ERR_STARTTLS         = 691,
	ERR_INVALIDMODEPARAM = 696,

	ERR_NOPRIVS = 723,

	ERR_NICKLOCKED  = 902,
	ERR_SASLFAIL    = 904,
	ERR_SASLTOOLONG = 905,
	ERR_SASLABORTED = 906, 
	ERR_SASLALREADY = 907,

	// IRCv3 Errors
	ERR_INVALIDCAPCMD = 410,
}


// Inclusive Ranges
@(rodata)
RPL_RANGES := [?]struct {s, e: Response_Code} {
	{  RC(1),  RC(99)}, {RC(200), RC(399)},
	{RC(670), RC(671)}, {RC(704), RC(706)},
	{RC(900), RC(901)}, {RC(903), RC(903)}, 
	{RC(908), RC(908)}, 
} 

// Inclusive Ranges
@(rodata)
ERR_RANGES := [?]struct {s, e: Response_Code} {
	{RC(400), RC(491)}, {RC(501), RC(502)}, 
	{RC(524), RC(525)}, {RC(691), RC(691)}, 
	{RC(696), RC(696)}, {RC(723), RC(723)}, 
	{RC(902), RC(902)}, {RC(904), RC(907)}, 
}


is_reply_code :: proc(code: Response_Code) -> bool {
	if code < min(Response_Code) || code > max(Response_Code) {
		return false
	}
	
	for r in RPL_RANGES {
		if r.s <= code && code <= r.e {
			return true
		}
	}
	return false
}

is_error_code :: proc(code: Response_Code) -> bool {
	if code < min(Response_Code) || code > max(Response_Code) {
		return false
	}

	for r in ERR_RANGES {
		if r.s <= code && code <= r.e {
			return true
		}
	}
	return false
}


@(private)
is_valid_code_range :: proc(code: Response_Code) -> bool {
	return is_reply_code(code) || is_error_code(code)
}


is_valid_code :: proc(code: Response_Code) -> bool {
	if code < min(Response_Code) || code > max(Response_Code) {
		return false
	}
	return Valid_Response_Codes[code]
}


@(rodata)
Valid_Response_Codes := #sparse [Response_Code]bool {
	.None = false,

	// 1 to 99 client-server connections only
	.RPL_WELCOME  = true,
	.RPL_YOURHOST = true,
	.RPL_CREATED  = true,
	.RPL_MYINFO   = true,
	.RPL_ISUPPORT = true,
	.RPL_BOUNCE   = true,

	// 200 to 399 all connections
	.RPL_STATSLINKINFO = true,
	.RPL_STATSCOMMANDS = true,
	.RPL_STATSCLINE    = true,
	.RPL_STATSILINE    = true,
	.RPL_STATSKLINE    = true,
	.RPL_ENDOFSTATS    = true,
	.RPL_UMODEIS       = true,
	.RPL_STATSLLINE    = true,
	.RPL_STATSUPTIME   = true,
	.RPL_STATSOLINE    = true,
	.RPL_STATSHLINE    = true,
	.RPL_LUSERCLIENT   = true,
	.RPL_LUSEROP       = true,
	.RPL_LUSERUNKNOWN  = true,
	.RPL_LUSERCHANNELS = true,
	.RPL_LUSERME       = true,
	.RPL_ADMINME       = true,
	.RPL_ADMINLOC1     = true,
	.RPL_ADMINLOC2     = true,
	.RPL_ADMINEMAIL    = true,
	.RPL_TRYAGAIN      = true,
	.RPL_LOCALUSERS    = true,
	.RPL_GLOBALUSERS   = true,
	.RPL_WHOISCERTFP   = true,

	.RPL_NONE            = true,
	.RPL_AWAY            = true, 
	.RPL_USERHOST        = true,
	.RPL_UNAWAY          = true,
	.RPL_NOWAWAY         = true,
	.RPL_WHOISREGNICK    = true,
	.RPL_WHOISUSER       = true,
	.RPL_WHOISSERVER     = true,
	.RPL_WHOISOPERATOR   = true,
	.RPL_WHOWASUSER      = true,
	.RPL_ENDOFWHO        = true,
	.RPL_WHOISIDLE       = true,
	.RPL_ENDOFWHOIS      = true,
	.RPL_WHOISCHANNELS   = true,
	.RPL_WHOISSPECIAL    = true,
	.RPL_LISTSTART       = true,
	.RPL_LIST            = true,
	.RPL_LISTEND         = true,
	.RPL_CHANNELMODEIS   = true,
	.RPL_CREATIONTIME    = true,
	.RPL_WHOISACCOUNT    = true,
	.RPL_NOTOPIC         = true,
	.RPL_TOPIC           = true,
	.RPL_TOPICWHOTIME    = true,
	.RPL_INVITELIST      = true, // 'INVITE' COMMAND. Some use 346 because of RFC2812.
	.RPL_ENDOFINVITELIST = true, // 'INVITE' COMMAND. Some use 347 because of RFC2812.
	.RPL_WHOISACTUALLY   = true,
	.RPL_INVITING        = true,
	.RPL_INVEXLIST       = true, // 'MODE' COMMAND. Sometimes is RPL_INVITELIST because of RFC2812.
	.RPL_ENDOFINVEXLIST  = true, // 'MODE' COMMAND. Sometimes is RPL_ENDOFINVITELIST because of RFC2812.
	.RPL_EXCEPTLIST      = true,
	.RPL_ENDOFEXCEPTLIST = true,
	.RPL_VERSION         = true,
	.RPL_WHOREPLY        = true,
	.RPL_NAMREPLY        = true,
	.RPL_LINKS           = true,
	.RPL_ENDOFLINKS      = true,
	.RPL_ENDOFNAMES      = true,
	.RPL_BANLIST         = true,
	.RPL_ENDOFBANLIST    = true,
	.RPL_ENDOFWHOWAS     = true,
	.RPL_INFO            = true,
	.RPL_MOTD            = true,
	.RPL_ENDOFINFO       = true,
	.RPL_MOTDSTART       = true,
	.RPL_ENDOFMOTD       = true,
	.RPL_WHOISHOST       = true,
	.RPL_WHOISMODES      = true,
	.RPL_YOUREOPER       = true,
	.RPL_REHASHING       = true,
	.RPL_TIME            = true,

	// Other RPL
	.RPL_STARTTLS    = true,
	.RPL_WHOISSECURE = true,

	.RPL_HELPSTART = true,
	.RPL_HELPTXT   = true,
	.RPL_ENDOFHELP = true,

	.RPL_LOGGEDIN    = true,
	.RPL_LOGGEDOUT   = true,
	.RPL_SASLSUCCESS = true,
	.RPL_SASLMECHS   = true,

	// Errors
	.ERR_UNKNOWNERROR      = true,
	.ERR_NOSUCHNICK        = true,
	.ERR_NOSUCHSERVER      = true,
	.ERR_NOSUCHCHANNEL     = true,
	.ERR_CANNOTSENDTOCHAN  = true,
	.ERR_TOOMANYCHANNELS   = true,
	.ERR_WASNOSUCHNICK     = true,
	.ERR_TOOMANYTARGETS    = true,
	.ERR_NOORIGIN          = true,
	.ERR_NORECIPIENT       = true,
	.ERR_NOTEXTTOSEND      = true,
	.ERR_NOTOPLEVEL        = true,
	.ERR_WILDTOPLEVEL      = true,
	.ERR_INPUTTOOLONG      = true,
	.ERR_UNKNOWNCOMMAND    = true,
	.ERR_NOMOTD            = true,
	.ERR_NONICKNAMEGIVEN   = true,
	.ERR_ERRONEUSNICKNAME  = true,
	.ERR_NICKNAMEINUSE     = true,
	.ERR_NICKCOLLISION     = true,
	.ERR_USERNOTINCHANNEL  = true,
	.ERR_NOTONCHANNEL      = true,
	.ERR_USERONCHANNEL     = true,
	.ERR_NOTREGISTERED     = true,
	.ERR_NEEDMOREPARAMS    = true,
	.ERR_ALREADYREGISTERED = true,
	.ERR_PASSWDMISMATCH    = true,
	.ERR_YOUREBANNEDCREEP  = true,
	.ERR_INVALIDUSERNAME   = true,
	.ERR_CHANNELISFULL     = true,
	.ERR_UNKNOWNMODE       = true,
	.ERR_INVITEONLYCHAN    = true,
	.ERR_BANNEDFROMCHAN    = true,
	.ERR_BADCHANNELKEY     = true,
	.ERR_BADCHANMASK       = true,
	.ERR_NOPRIVILEGES      = true,
	.ERR_CHANOPRIVSNEEDED  = true,
	.ERR_CANTKILLSERVER    = true,
	.ERR_NOOPERHOST        = true,

	.ERR_UMODEUNKNOWNFLAG  = true,
	.ERR_USERSDONTMATCH    = true,
	.ERR_HELPNOTFOUND      = true,
	.ERR_INVALIDKEY        = true,

	.ERR_STARTTLS          = true,
	.ERR_INVALIDMODEPARAM  = true,

	.ERR_NOPRIVS = true,

	.ERR_NICKLOCKED  = true,
	.ERR_SASLFAIL    = true,
	.ERR_SASLTOOLONG = true,
	.ERR_SASLABORTED = true, 
	.ERR_SASLALREADY = true,

	// IRCv3 Errors
	.ERR_INVALIDCAPCMD = true,
}
