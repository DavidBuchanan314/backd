from typing import List, Self, Optional
from core import SyscallsAarch64, BackdClientSession

async def listdir(sess: BackdClientSession, dir_path: str) -> List[str]:
	dfd = await sess.cmd_syscall_helper(SyscallsAarch64.openat, 0, dir_path, 0, 0)
	entries = []

	# get all the dirents
	while True:
		await sess.cmd_write_mem(sess.buf_addr, bytes(sess.buf_len)) # zero the buffer (annoyingly expensive)
		dentlen = await sess.cmd_syscall_helper(SyscallsAarch64.getdents64, dfd, sess.buf_addr, sess.buf_len)
		if dentlen == 0:
			break
		dentbuf = await sess.cmd_read_mem(sess.buf_addr, dentlen)
		off = 0
		while off < len(dentbuf):
			reclen = int.from_bytes(dentbuf[off+8+8:off+8+8+2], "little")
			name = dentbuf[off+8+8+2+1:off+reclen-2].rstrip(b"\x00").decode()
			entries.append(name)
			off += reclen

	# close
	await sess.cmd_syscall_helper(SyscallsAarch64.close, dfd)

	return entries

async def read_file(sess: BackdClientSession, path: str) -> Optional[bytes]:
	"""
	try to read whole file

	XXX: only works if the whole file fits inside buf_len
	"""
	fd = await sess.cmd_syscall_helper(SyscallsAarch64.openat, 0, path, 0, 0)
	if fd < 0:
		return None
	res = b""
	while readlen := await sess.cmd_syscall_helper(SyscallsAarch64.read, fd, sess.buf_addr, sess.buf_len):	
		if readlen < 0:
			await sess.cmd_syscall_helper(SyscallsAarch64.close, fd)
			return None
		res += await sess.cmd_read_mem(sess.buf_addr, readlen)
	await sess.cmd_syscall_helper(SyscallsAarch64.close, fd)
	return res
