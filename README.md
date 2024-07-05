# backd
Current status: Planning phase.

### Planned features:
- Synchronous protocol, but supporting multiple concurrent connections.
- The "server" side should be as simple as possible, with as much work as possible offloaded into the client.
- Performance is a non-priority (You're expected to be running this on a local network, we don't care about excess round trips)
- Mostly acts as a thin wrapper around syscalls, but since syscall numbers are non-portable we'll need our own mapping table.
- Filesystem access (open/seek/read/write/getdents64)
- process_vm_readv/process_vm_writev
- memfd_create
- execve (optionally with dup2'd stdio onto the requesting socket)

### Implementation:

The server (`backd`) will have a static buffer of fixed size (maybe around 1MB?).

On a new connection, the server tells the client the memory address of the buffer, the size of the buffer, and the cpu architecture (and maybe some other stuff I haven't thought of yet). This info is length-prefixed for future compatibility.

Requests all have the same format (little-endian ints):
```
[16-bit cmd_id][16-bit header_len][32-bit body_len]
```

Responses similarly:
```
[32-bit length]
```

A negative response length indicates an error.

There are just 3 request types:
- write memory `cmd_id=0, header=[64-bit addr], body=[the data to write]`, returns empty response.
- Read memory `cmd_id=1, header=[64-bit addr][32-bit length], body=[]`, returns `length` bytes as response.
- Do syscall (and return result) `cmd_id=2, header=[as many 64-bit ints as there are args for the syscall], body=[]`, returns 64-bit result value (LE) (nb, this is still prefixed by the response length, which is always 8) (unless I implement support for 32-bit platforms at some point...)
