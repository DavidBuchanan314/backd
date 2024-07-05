import asyncio
from typing import List, Self, Optional

class SyscallsAarch64:
	openat = 56
	close = 57
	getdents64 = 61
	read = 63
	write = 64

class BackdClientSession():
	def __init__(self, rhost:str, rport:int) -> None:
		self.rhost = rhost
		self.rport = rport

		# make sure we only ever have one request in-flight at a time
		self.request_lock = asyncio.Lock()

	async def connect(self) -> None:
		self.reader, self.writer = await asyncio.open_connection(
			self.rhost, self.rport
		)
		server_info_len = int.from_bytes(await self.reader.readexactly(4), "little")
		server_info = await self.reader.readexactly(server_info_len)
		self.buf_len = int.from_bytes(server_info[:4], "little")
		self.buf_addr = int.from_bytes(server_info[4:12], "little")
		print("buffer @", hex(self.buf_addr))

	async def shutdown(self):
		self.writer.close()
		await self.writer.wait_closed()

	async def do_request(self, cmd_id: int, header: bytes, body: bytes):
		async with self.request_lock:
			msg = (
				cmd_id.to_bytes(2, "little") +
				len(header).to_bytes(2, "little") +
				len(body).to_bytes(4, "little") +
				header + body
			)
			self.writer.write(msg)
			await self.writer.drain()
			response_len = int.from_bytes(await self.reader.readexactly(4), byteorder="little", signed=True)
			if response_len < 0:
				raise Exception("request failed")
			response = await self.reader.readexactly(response_len)
			return response
	
	async def cmd_write_mem(self, addr: int, buf: bytes):
		res = await self.do_request(
			cmd_id=0,
			header=addr.to_bytes(8, "little"),
			body=buf
		)
		assert(len(res) == 0)
	
	async def cmd_read_mem(self, addr: int, length: int):
		res = await self.do_request(
			cmd_id=1,
			header=addr.to_bytes(8, "little") + length.to_bytes(4, "little"),
			body=b""
		)
		assert(len(res) == length)
		return res
	
	async def cmd_raw_syscall(self, sys_no: int, *args):
		res = await self.do_request(
			cmd_id=2,
			header=sys_no.to_bytes(2, "little") + b"".join(arg.to_bytes(8, "little") for arg in args),
			body=b""
		)
		assert(len(res) == 8)
		res = int.from_bytes(res, byteorder="little", signed=True)
		return res
	
	async def cmd_syscall_helper(self, sys_no: int, *args):
		buffer = b""
		int_args = []
		for arg in args:
			match arg:
				case int():
					int_args.append(arg & 0xffff_ffff_ffff_ffff)
				case bytes():
					int_args.append(self.buf_addr + len(buffer))
					buffer += arg
				case str():
					int_args.append(self.buf_addr + len(buffer))
					buffer += arg.encode() + b"\x00"
		if buffer:
			await self.cmd_write_mem(self.buf_addr, buffer)
		return await self.cmd_raw_syscall(sys_no, *int_args)

	async def __aenter__(self) -> Self:
		await self.connect()
		return self

	async def __aexit__(self, exc_type, exc_val, exc_tb) -> Optional[bool]:
		await self.shutdown()
