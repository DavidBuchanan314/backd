import asyncio

from core import BackdClientSession, SyscallsAarch64
from proc import pgrep, get_maps, dump_maps

async def main():
	async with BackdClientSession("127.0.0.1", 31337) as sess:
		print("connected")

		hello = b"hello, world!\n"
		res = await sess.cmd_syscall_helper(SyscallsAarch64.write, 1, hello, len(hello))
		print("res:", res)

		pid = await pgrep(sess, "python3")
		print("found", pid)

		maps = await get_maps(sess, pid)
		for map in maps:
			if "/libc.so" in map.name:
				print(map.name)
				libc_base = map.start
				break
		else:
			raise Exception("couldn't find libc")
		
		print("libc base @", hex(libc_base))

		await dump_maps(sess, pid, maps, "./dump/")

if __name__ == "__main__":
	asyncio.run(main())
