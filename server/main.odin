package basic_irc_server

@(require) import "core:log"
@(require) import "core:mem"
@(require) import "core:fmt"
@(require) import "base:runtime"

@(require) import com "../common"

main :: proc() { 
    context.logger = log.create_console_logger()
    defer log.destroy_console_logger(context.logger, runtime.default_allocator())
    
    /*
        track: mem.Tracking_Allocator
        mem.tracking_allocator_init(&track, context.allocator)
        context.allocator = mem.tracking_allocator(&track)

        temp_track: mem.Tracking_Allocator
        mem.tracking_allocator_init(&temp_track, context.temp_allocator)
        context.temp_allocator = mem.tracking_allocator(&temp_track)

        defer {
            for addr, leak in temp_track.allocation_map {
                fmt.eprintfln("%v leak %v temp %v bytes", leak.location, addr, leak.size)
            }
            for bad_free in temp_track.bad_free_array {
                fmt.eprintfln("temp %v allocation %p was freed badly", bad_free.location, bad_free.memory)
            }
            mem.tracking_allocator_destroy(&temp_track)

            for addr, leak in track.allocation_map {
                fmt.eprintfln("%v leak %v alloc %v bytes", leak.location, addr, leak.size)
            }
            for bad_free in track.bad_free_array {
                fmt.eprintfln("%v allocation %p was freed badly", bad_free.location, bad_free.memory)
            }
            mem.tracking_allocator_destroy(&track)
        }
    */
    
    s: Server
    init_server(&s, DEFAULT_ADDRESS)
    defer server_cleanup(&s)
    // set_ctrl_hander()
    server_runner(&s)


}
