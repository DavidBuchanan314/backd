# backd
Current status: Planning phase.

Planned features:
- Synchronous protocol, but supporting multiple concurrent connections.
- The "server" side should be as simple as possible, with as much work as possible offloaded into the client.
- Performance is a non-priority (You're expected to be running this on a local network, we don't care about excess round trips)
- Mostly acts as a thin wrapper around syscalls, but since syscall numbers are non-portable we'll need our own mapping table.
- Filesystem access (open/seek/read/write/getdents64)
- process_vm_readv/process_vm_writev
- memfd_create
- execve (optionally with dup2'd stdio onto the requesting socket)
