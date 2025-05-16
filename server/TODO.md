
- [X] Rework all cmd_* to take a buffer
    - [ ] Work out where it's worth to send the buffer

- [ ] Move to an id based system:
    - Is UUID good enough?
    - [ ] Sender
    - Helpers:
        - [ ] user -> id
        - [ ] nick -> id
        - [ ] id   -> Client
    - Channel:
        - [ ] `admin`
        - [ ] `users`
    - Server:
        - [ ] `nicks`
        - [ ] `clients`
        - [ ] `admin`

- [ ] More threading ya:
    - [X] Atomic wrapper type
    - [ ] Atomic wrapper procs
    - Server:
    - Client:
        - [ ] Thread proc
        - [ ] `to_send`   -> sync/chan
    - Channel: 
        - [ ] Thread proc
        - [ ] `to_remove` -> sync/chan
        - [ ] `to_send`   -> sync/chan

- Ensure conplince with
    - [ ] https://modern.ircdocs.horse/#compatibility-with-incorrect-software

- [ ] Remove virtual arenas from threads. Assume default temp alloc is used.