
- [X] Rework all cmd_* to take a buffer
    - [X] Work out where it's worth to send the buffer

- [-] Move to an id based system:
    - Is UUID good enough?
    - [-] Sender
    - Helpers:
        - [-] user -> id
        - [-] nick -> id
        - [-] id   -> Client
    - Channel:
        - [-] `admin`
        - [-] `users`
    - Server:
        - [-] `nicks`
        - [-] `clients`
        - [-] `admin`

- [X] More threading ya:
    - [-] Atomic wrapper type
    - [-] Atomic wrapper procs
    - Server:
    - Client:
        - [X] Thread proc
        - [-] `to_send`   -> sync/chan
        - [X] Add messages to cache when can't send
    - Channel: 
        - [X] Thread proc
        - [-] `to_remove` -> sync/chan
        - [-] `to_send`   -> sync/chan

- Ensure conplince with
    - [ ] https://modern.ircdocs.horse/#compatibility-with-incorrect-software

- [X] Remove virtual arenas from threads. Assume default temp alloc is used.

- [-] Should `Message.cmd` be an enum???
    I remember thinking it wouldn't be worth it during parser because I'd
    still need to save the string on Unknown command.
    Plus I'd still need check all values or use a map & 
    I'm only checking the cmds once anyways.

- [X] Implement Capability Negotiation

- [X] Add rate limiting to Clients

- [-] Messages should only be allocated to the destination allocator when it can be sent.  
    Allows for the allocator to be an arena. 
    Aplicable to `Channel/Client.to_send` & `Client.mess_cache`

- [-] `Server.client/channel/nick_lock` could probably be moved to a `rwmutex`

- [X] Have cleint threads to cleanup after themselfs

- [ ] https://github.com/progval/irctest

- [X] Handle `Ctrl` properaly

- [X] Support `Ctrl + BP` for word removel

- [X] General cleanup
    - [X] Add Documentation
    - [X] Formating
    - [X] Compliance with `-vet -strict-style -vet-tabs -disallow-do -warnings-as-errors`
