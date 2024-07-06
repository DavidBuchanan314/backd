from core import SyscallsAarch64, BackdClientSession

async def sys_kill(sess: BackdClientSession, pid: int, sig: int) -> int:
	return await sess.cmd_syscall_helper(SyscallsAarch64.kill, pid, sig)
