package basic_irc_client

import "base:runtime"
import ir "base:intrinsics"

import "core:io"
import "core:os"
import "core:net"
import "core:time"
import "core:sync"
import sa "core:container/small_array"

import "../common"


TAGS_SIZE         :: 8191
MESSAGE_SIZE      :: 512
MAX_MESSAGE_SIZE  :: TAGS_SIZE + MESSAGE_SIZE

NET_READ_SIZE   :: 512
NET_BUFFER_SIZE :: MAX_MESSAGE_SIZE + NET_READ_SIZE


NET_TIMEOUT         :: time.Millisecond * 500
THREAD_TIMEOUT      :: time.Millisecond * 10
MESS_PRINT_TIMEOUT  :: time.Millisecond * 20
REPLY_CHECK_TIMEOUT :: time.Millisecond * 5
RECONNECT_TIMEOUT   :: time.Millisecond * 100 
INPUT_COMNSUME_TIME :: time.Millisecond * 50

@(rodata)
MESS_END     := []byte{'\r', '\n'}
MESS_END_STR :: "\r\n"


#assert(512 <= MAX_MESSAGE_SIZE)
#assert(0 < NET_READ_SIZE)
#assert(NET_READ_SIZE + MAX_MESSAGE_SIZE <= NET_BUFFER_SIZE)

PRINT_BUFFER_SIZE :: 640
INPUT_BUFFER_SIZE :: MAX_MESSAGE_SIZE

INPUT_STR    :: " > "
CLEAR_LINE   :: "\e[2K\r"
#assert(MESSAGE_SIZE + len(INPUT_STR) + len(CLEAR_LINE) + 1 < PRINT_BUFFER_SIZE)


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
}


Error :: union #shared_nil { 
	runtime.Allocator_Error, 
	net.Network_Error, 
	os.Error,
	io.Error,

	IRC_Errors, 
}


Net_Buffer :: struct {
	buf: [NET_BUFFER_SIZE]byte `fmt:"-"`,
	pos: int, 
}


Client :: struct {
	user: string,
	nick: string,
	real: string,
	pass: string, // oh look plain text passwords very secure /s

	server: Server,
	sock:   net.TCP_Socket,
	chan:   string,

	net:    Net_Buffer,
	parsed: [dynamic]Message `fmt:"-"`,

	input_buf: sa.Small_Array(INPUT_BUFFER_SIZE, byte) `fmt:"-"`,
	mutex:     sync.Ticket_Mutex,

	pause_input: bool, // Atmoic

	pause_thread:  bool, // Atomic
	pause_barrier: sync.Barrier,

	close_thread:  bool, // Atomic
	close_barrier: sync.Barrier,
}


Server :: struct {
	url:    string, 
	name:   string, 
	socket: net.Socket, 
}


Sender_Type :: enum {
	None, 
	Invalid, 
	Server, 
	Self, 
	User, 
	Sys, 
	Sys_Err,
}


Sender :: struct {
	name: string,
	type: Sender_Type,
}


Message :: struct {
	recived: time.Time,
	// All other fields are views/slices into this string.
	raw:     string `fmt:"-"`,
	tags:    string,
	sender:  Sender,
	cmd:     string,
	code:    common.Response_Code,
	params:  []string,
	tail:    string,
}

