#+private
#+build linux, darwin, netbsd, openbsd, freebsd
package basic_irc_client

import "base:runtime"

import "core:c"
import "core:os"
import "core:fmt"
import "core:strings"
import "core:thread"
import psx "core:sys/posix"

sig_handler :: proc "c" (sig: c.int) {
	context = runtime.default_context()
	os.write_string(os.stdout, "Are you sure you'd like to quit? [Y/n]")
	buf: [4]u8

	for {
		n, err := os.read(os.stdin, buf[:])
		if err != nil {
			fmt.println("Failed to get input because of:", err)
			os.exit(-1)
		}
		if n == 0 {
			os.exit(0)
		}
		switch buf[0] {
		case 'y', 'Y', '\n':
			os.exit(0)
		case 'n', 'N':
			return
		}
	}
}


_set_ctrl_hander :: proc() -> (ok: bool) {
	if psx.signal(psx.SIGINT, sig_handler) == psx.SIG_ERR {
		err := psx.get_errno()
		fmt.printf("Unable to set console output\nError: %v (%v)", err, int(err))
		return false
	}
	if psx.signal(psx.SIGTSTP, sig_handler) == psx.SIG_ERR {
		err := psx.get_errno()
		fmt.printf("Unable to set console output\nError: %v (%v)", err, int(err))
		return false
	}
	return true
}


when ODIN_OS == .Darwin {
	foreign import lib "system:System.framework"
} else  {
	foreign import lib "system:pthread"
} 

when ODIN_OS == .NetBSD {
	foreign lib {
		pthread_setname_np :: proc(thread: pthread_t, name: cstring, #c_vararg arg: ..any) -> psx.Errno ---
	}
	set_thead_name :: proc(name: string, t: ^thread.Thread) {
		str := strings.clone_to_cstring(name, context.temp_allocator)
		pthread_setname_np(t.unix_thread, str)
	}

} else when ODIN_OS == .Darwin {
	foreign lib {
		pthread_setname_np :: proc(cstring) -> c.int ---
	}
	set_thead_name :: proc(name: string, t: ^thread.Thread) {
		str := strings.clone_to_cstring(name, context.temp_allocator)
		pthread_setname_np(str)
	}

} else when ODIN_OS == .OpenBSD {
	foreign lib {
		pthread_set_name_np :: proc(thread: pthread_t, name: cstring) ---
	}
	set_thead_name :: proc(name: string, t: ^thread.Thread) {
		str := strings.clone_to_cstring(name, context.temp_allocator)
		pthread_set_name_np(t.unix_thread, str)
	}

} else when ODIN_OS == .Linux || ODIN_OS == .FreeBSD {
	foreign lib {
		pthread_setname_np :: proc(thread: pthread_t, name: cstring) -> psx.Errno ---
	}
	set_thead_name :: proc(name: string, t: ^thread.Thread) {
		str := strings.clone_to_cstring(name, context.temp_allocator)
		pthread_setname_np(t.unix_thread, str)
	}
}
