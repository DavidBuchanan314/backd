from typing import List, Self, Optional
from core import SyscallsAarch64, BackdClientSession

async def sys_open(sess: BackdClientSession, path: str, flags: int=0, mode: int=0) -> int:
	return await sess.cmd_syscall_helper(SyscallsAarch64.openat, -100, path, flags, mode)

async def sys_close(sess: BackdClientSession, fd: int) -> None:
	await sess.cmd_syscall_helper(SyscallsAarch64.close, fd)

async def lseek(sess: BackdClientSession, fd: int, pos: int, whence: int=0): # SEEK_SET
	return await sess.cmd_syscall_helper(SyscallsAarch64.lseek, fd, pos, whence)

# read all of n bytes
async def readn(sess: BackdClientSession, fd: int, length: int) -> Optional[bytes]:
	res = b""
	while len(res) < length:
		readlen = await sess.cmd_syscall_helper(SyscallsAarch64.read, fd, sess.buf_addr, length - len(res))
		print("read", readlen)
		if readlen < 0:
			print("readlen error", readlen)
			return None
		res += await sess.cmd_read_mem(sess.buf_addr, readlen)
	return res

async def listdir(sess: BackdClientSession, dir_path: str) -> List[str]:
	dfd = await sess.cmd_syscall_helper(SyscallsAarch64.openat, 0, dir_path, 0, 0)
	entries = []

	# get all the dirents
	while True:
		dentlen = await sess.cmd_syscall_helper(SyscallsAarch64.getdents64, dfd, bytes(sess.buf_len), sess.buf_len)
		#print("dentlen", dentlen)
		if dentlen == 0:
			break
		dentbuf = await sess.cmd_read_mem(sess.buf_addr, dentlen)
		off = 0
		while off < len(dentbuf):
			reclen = int.from_bytes(dentbuf[off+8+8:off+8+8+2], "little")
			name = dentbuf[off+8+8+2+1:off+reclen].rstrip(b"\x00")
			#print(name)
			entries.append(name.decode())
			off += reclen

	await sys_close(sess, dfd)

	return entries

async def read_file(sess: BackdClientSession, path: str) -> Optional[bytes]:
	"""
	try to read whole file
	"""
	fd = await sys_open(sess, path)
	if fd < 0:
		return None
	res = b""
	while readlen := await sess.cmd_syscall_helper(SyscallsAarch64.read, fd, sess.buf_addr, sess.buf_len):
		if readlen < 0:
			print("readlen error", readlen)
			await sys_close(sess, fd)
			return None
		res += await sess.cmd_read_mem(sess.buf_addr, readlen)
	await sys_close(sess, fd)
	return res
