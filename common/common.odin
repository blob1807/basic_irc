package basic_irc_common

import "core:unicode/utf8"


is_valid_nick :: proc(nick: string) -> bool {
    if nick == "" {
        return false
    }

    // Forbidden prefix runes
    fr, _ := utf8.decode_rune(nick)
    switch fr {
    case '#', '$', ':', '&', '~', '%', '+', '@':
        return false
    }

    // Forbidden runes & formating
    for r, p in nick {
        switch r {
        case ' ', ',', '*', '?', '!', 
        '\x02', '\x1D', '\x1F', '\x1E', 
        '\x11', '\x03', '\x04', '\x16', '\x0F', 
        utf8.RUNE_ERROR:
            return false
        case '\e':
            if p+1 < len(nick) \
            && nick[p+1] == '[' {
                return false
            }
        }
    }

    return true
}


is_valid_user :: proc(user: string) -> bool {
    if user == "" {
        return false
    }

    // Forbid formating & invalid runes
    for r, p in user {
        switch r {
        case '\x02', '\x1D', '\x1F', '\x1E', 
        '\x11', '\x03', '\x04', '\x16', '\x0F',
        utf8.RUNE_ERROR:
            return false
        case '\e':
            if p+1 < len(user) \
            && user[p+1] == '[' {
                return false
            }
        }
    }

    return true
}

is_valid_real :: proc(real: string) -> bool {
    if real == "" {
        return false
    }
    
    // Forbid invalid runes
    for r in real {
        if r == utf8.RUNE_ERROR {
            return false
        }
    }
    return true
}


contains_formating :: proc(str: string) -> bool {
    if str == "" {
        return false
    }

    for r, p in str {
        switch r {
        case '\x02', '\x1D', '\x1F', '\x1E', 
        '\x11', '\x03', '\x04', '\x16', '\x0F':
            return true
        case '\e':
            if p+1 < len(str) \
            && str[p+1] == '[' {
                return true
            }
        }
    }

    return false
}


is_equal :: proc(a, b: string) -> bool {
    if len(a) != len(b) {
        return false
    } else if raw_data(a) == raw_data(b) {
        return true
    }

    for i in 0..<len(a) {
        x, y := a[i], b[i]
        if 'A' <= x && x <= 'Z' {
            x |= 32
        } if 'A' <= y && y <= 'Z' {
            y |= 32
        }

        if x != y {
            return false
        }
    }

    return true
}


is_equal_utf8 :: proc(a_in, b_in: string) -> bool {
    if len(a_in) == len(b_in) \ 
    && raw_data(a_in) == raw_data(b_in) {
        return true
    }
    
    _a, _b := a_in, b_in
    size := min(len(a_in), len(b_in)) + 1

    for _ in 0..<size {
        x, xn := utf8.decode_rune(_a)
        y, yn := utf8.decode_rune(_b)

        if x == utf8.RUNE_ERROR \
        || y == utf8.RUNE_ERROR {
            break
        }
        
        _a = _a[xn:]
        _b = _b[yn:]

        if 'A' <= x && x <= 'Z' {
            x |= 32
        } if 'A' <= y && y <= 'Z' {
            y |= 32
        }

        if x != y {
            return false
        }
    }

    return _a == "" && _b == ""
}

