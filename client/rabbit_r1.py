import asyncio
import time
import math
import os
import ast
import pwn
import signal

pwn.context.arch = "arm64"

from core import BackdClientSession, SyscallsAarch64
from proc import pgrep, get_maps, dump_maps
from fs import sys_open, sys_close, read_file, lseek, readn, listdir
from misc import sys_kill

from zip_offsets import get_file_offsets

async def set_orientation(sess: BackdClientSession, angle: int):
	fd = await sys_open(sess, "/sys/devices/platform/step_motor_ms35774/orientation", os.O_WRONLY)
	#print("fd", fd)
	val = f"{angle}\n"
	res = await sess.cmd_syscall_helper(SyscallsAarch64.write, fd, val, len(val))
	#print(res)
	await sys_close(sess, fd)

async def stepper_fun(sess: BackdClientSession):
	while True:
		await set_orientation(sess, 0)
		time.sleep(0.5)
		await set_orientation(sess, 180)
		time.sleep(0.5)

def first_in_maps(maps, name):
	for map in maps:
		if name in map.name:
			print(map.name)
			return map.start
	else:
		raise Exception(f"couldn't find {name}")

async def main():
	async with BackdClientSession("192.168.0.91", 31338) as sess:
		print("connected")

		hello = b"hello, world!\n"
		res = await sess.cmd_syscall_helper(SyscallsAarch64.write, 1, hello, len(hello))
		print("res:", res)

		pid = await pgrep(sess, "tech.rabbit.r1launcher.r1", progress=True)
		#pid = 3025
		print("found", pid)

		maps = await get_maps(sess, pid)
		libc_base = first_in_maps(maps, "/libc.so")
		libdl_base = first_in_maps(maps, "/libdl.so")
		liblog_base = first_in_maps(maps, "/liblog.so")
		print("libc base @", hex(libc_base))
		print("libdl base @", hex(libdl_base))
		print("liblog base @", hex(liblog_base))

		#await dump_maps(sess, pid, maps, "./dump/")
		#await stepper_fun(sess)

		#with open("RabbitLauncher.apk", "wb") as outfile:
		#	outfile.write(await read_file(sess, "/system/app/RabbitLauncher/RabbitLauncher.apk"))
		#with open("libc.so", "wb") as outfile:
		#	outfile.write(await read_file(sess, "/apex/com.android.runtime/lib64/bionic/libc.so"))
		#with open("libdl.so", "wb") as outfile:
		#	outfile.write(await read_file(sess, "/apex/com.android.runtime/lib64/bionic/libdl.so"))
		#with open("libssl.so", "wb") as outfile:
		#	outfile.write(await read_file(sess, "/system/lib64/libssl.so"))
		#with open("libjavacrypto.so", "wb") as outfile:
		#	outfile.write(await read_file(sess, "/apex/com.android.conscrypt/lib64/libjavacrypto.so"))
		#with open("liblog.so", "wb") as outfile:
		#	outfile.write(await read_file(sess, "/system/lib64/liblog.so"))

		libc = pwn.ELF("./dumped_libs/libc.so")
		libc.address = libc_base

		libdl = pwn.ELF("./dumped_libs/libdl.so")
		libdl.address = libdl_base

		liblog = pwn.ELF("./dumped_libs/liblog.so")
		liblog.address = liblog_base

		zip_offsets = get_file_offsets("./RabbitLauncher.apk")
		revmap = {v: k for k, v in zip_offsets.items()}
		lib_offsets = {}
		for map in maps:
			if not map.name.endswith("/RabbitLauncher.apk"):
				continue
			if map.offset in revmap:
				libname = revmap[map.offset]
				print(f"{libname} @ {hex(map.start)}")
				lib_offsets[libname] = map.start
		
		# find libc code-cave
		libc_plt = libc.get_section_by_name(".plt")
		plt_end = libc_base + libc_plt.header.sh_addr + libc_plt.header.sh_size
		cave_end = (plt_end + 0xfff) &~ 0xfff
		cave_size = cave_end - plt_end
		print(f"{hex(cave_size)} byte code cave identified @ {hex(plt_end)}")

		await sys_kill(sess, pid, signal.SIGSTOP)
		# stop *all* the theads in this process (TODO: maybe use cgroup freezer?)
		#for task in await listdir(sess, f"/proc/{pid}/task/"):
		#	if not task.isnumeric():
		#		continue
		#	task = int(task)
		#	await sys_kill(sess, task, signal.SIGSTOP)

		proc_syscall = (await read_file(sess, f"/proc/{pid}/syscall")).decode().strip()
		print(proc_syscall)
		parts = proc_syscall.split(" ")
		ip = ast.literal_eval(parts[-1])
		sp = ast.literal_eval(parts[-2])
		print("ip @", hex(ip))
		patch_site = ip

		trampoline = pwn.asm(f"""
			ldr x1, ={plt_end} // jump into code cave
			br x1
		""")
		pwn.log.info("trampoline:")
		pwn.log.info(pwn.disasm(trampoline))

		memfd = await sys_open(sess, f"/proc/{pid}/mem", os.O_RDWR)
		await lseek(sess, memfd, patch_site)
		backup = await readn(sess, memfd, len(trampoline))

		pwn.log.info("backup:")
		pwn.log.info(pwn.disasm(backup))

		# dlopen("/blah.so")
		# kill(self, SIGSTOP)
		# ret -4
		so_loader = pwn.asm(f"""
			stp fp, lr, [sp, #-0x30]!  // prologue
			mov fp, sp
			//str x0, [sp, #-0x10]
			
			// if we aren't the target pid, pretend nothing happened...
			//mov x8, #{SyscallsAarch64.gettid}
			//svc 0

			//ldr x1, ={pid}
			//cmp x0, x1
			//bne cleanup
		
			mov x8, #{SyscallsAarch64.kill}
			ldr x0, ={pid}
			mov x1, #{signal.SIGSTOP}
			svc 0

			//loop:
			mov x0, #4
			adr x1, logtag
			adr x2, logmsg
			ldr x3, ={liblog.sym['__android_log_print']}
			blr x3
			//b loop

			adr x0, path
			mov x1, #0
			//mov x2, #0
			ldr x2, ={libc_base}
			ldr x3, ={libdl.sym['__loader_dlopen']}
			blr x3

			mov x3, x0 // store dlopen result

			mov x0, #4
			adr x1, logtag
			adr x2, logmsg2
			ldr x4, ={liblog.sym['__android_log_print']}
			blr x4

			// TODO: only dlerror if dlopen failed...
			//ldr x3, ={libdl.sym['dlerror']}
			//blr x3
			//mov x2, x0

			//mov x0, #4
			//adr x1, logtag
			//ldr x4, ={liblog.sym['__android_log_print']}
			//blr x4

			//b .
cleanup:
			mov x0, #-4 // EINTR
			ldr x1, ={libc.symbols["__set_errno_internal"]}
			blr x1

			//mov x0, #-4

			//ldr x0, [sp, #-0x10]

			// epilogue
			ldp fp, lr, [sp], #0x30
			ret
			
			path:
				.asciz "/data/data/tech.rabbit.r1launcher.r1/nothingtoseehere.so"
			logtag:
				.asciz "hook"
			logmsg:
				.asciz "I'm being hooked!"

			logmsg2:
				.asciz "did dlopen: 0x%lx"
		""")
		assert(len(so_loader) < cave_size)

		# write code-cave
		await lseek(sess, memfd, plt_end)
		res = await sess.cmd_syscall_helper(SyscallsAarch64.write, memfd, so_loader, len(so_loader))
		print("res", res)

		# install trampopoline
		await lseek(sess, memfd, patch_site)
		res = await sess.cmd_syscall_helper(SyscallsAarch64.write, memfd, trampoline, len(trampoline))
		print("res", res)

		pwn.log.info("waking the process up again")

		# wait for the procss to wake up and SIGSTOP itself again
		while True:
			await sys_kill(sess, pid, signal.SIGCONT) # idk why we need to do this repeatedly...
			proc_syscall = (await read_file(sess, f"/proc/{pid}/syscall")).decode().strip()
			print(proc_syscall)
			parts = proc_syscall.split(" ")
			nr = ast.literal_eval(parts[0])
			ip = ast.literal_eval(parts[-1])
			sp = ast.literal_eval(parts[-2])
			if nr == -1 and (ip &~0xfff) == (plt_end &~0xfff):
				break
		
		#time.sleep(0.5)
		pwn.log.info("the process is waiting for us! removing the patch...")

		await lseek(sess, memfd, patch_site)
		res = await sess.cmd_syscall_helper(SyscallsAarch64.write, memfd, backup, len(backup))
		print("res", res)

		pwn.log.info("waking the process up for real this time")
		await sys_kill(sess, pid, signal.SIGCONT)
		#for task in await listdir(sess, f"/proc/{pid}/task/"):
		#	if not task.isnumeric():
		#		continue
		#	task = int(task)
		#	await sys_kill(sess, task, signal.SIGCONT)

		await sys_close(sess, memfd)

if __name__ == "__main__":
	asyncio.run(main())
