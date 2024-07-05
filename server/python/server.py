"""
This impl mainly exists for testing purposes.

It is single-threaded and accepts only one client at a time.
"""

import mmap
import ctypes
import socket

BUF_SIZE = 0x100000

def recvn(s: socket.socket, n: int):
	buf = b""
	while len(buf) < n:
		part = s.recv(n-len(buf))
		if not part:
			raise EOFError
		buf += part
	assert(len(buf) == n)
	return buf

def respond(s: socket.socket, msg: bytes):
	s.sendall(len(msg).to_bytes(4, "little") + msg)

def main():
	libc = ctypes.CDLL(None)
	buffer = mmap.mmap(-1, BUF_SIZE)
	buffer_addr = ctypes.addressof(ctypes.c_void_p.from_buffer(buffer))
	print("buffer @", hex(buffer_addr))

	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
		s.bind(("0.0.0.0", 31337))
		s.listen(1)

		while True:
			conn, addr = s.accept()
			print("connection from", addr)

			# send server info
			server_info = BUF_SIZE.to_bytes(4, "little") + buffer_addr.to_bytes(8, "little")
			respond(conn, server_info)

			while True:
				try:
					msg = recvn(conn, 8)
				except EOFError:
					break
				print(msg.hex())
				cmd_id = int.from_bytes(msg[:2], "little")
				hdr_len = int.from_bytes(msg[2:4], "little")
				body_len = int.from_bytes(msg[4:], "little")
				hdr = recvn(conn, hdr_len)
				body = recvn(conn, body_len)
				if cmd_id == 0:
					assert(hdr_len == 8)
					addr = int.from_bytes(hdr, "little")
					buffer[addr-buffer_addr:addr-buffer_addr+len(body)] = body
					respond(conn, b"")
				elif cmd_id == 1:
					assert(hdr_len == 12)
					addr = int.from_bytes(hdr[:8], "little")
					length = int.from_bytes(hdr[8:], "little")
					respond(conn, buffer[addr-buffer_addr:addr-buffer_addr+length])
				elif cmd_id == 2:
					sysno = int.from_bytes(hdr[:2], "little")
					args = [ctypes.c_ulonglong(int.from_bytes(hdr[i:i+8], "little")) for i in range(2, len(hdr), 8)]
					print("syscall", sysno, [arg for arg in args])
					res = libc.syscall(sysno, *args) & 0xffff_ffff_ffff_ffff
					respond(conn, res.to_bytes(8, "little"))
				else:
					conn.sendall(b"\xff\xff\xff\xff") # error
			
			conn.close()
		s.close()

if __name__ == "__main__":
	main()
