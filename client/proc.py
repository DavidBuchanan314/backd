import re
from typing import List, Optional
from tqdm import tqdm

from core import BackdClientSession
from fs import listdir, read_file, lseek, readn, sys_open, sys_close
from dataclasses import dataclass

async def get_argv(sess: BackdClientSession, pid: int) -> Optional[List[bytes]]:
	cmdline = await read_file(sess, f"/proc/{pid}/cmdline")
	if cmdline is None:
		return None
	return cmdline.split(b"\x00")

async def pgrep(sess: BackdClientSession, name: str, progress=False) -> int:
	name_bytes = name.encode()
	proc_entries = await listdir(sess, "/proc")
	proc_entries.reverse() # start with most recently spawned processes
	if progress:
		proc_entries = tqdm(proc_entries)
	for proc_entry in proc_entries:
		if not proc_entry.isdecimal():
			continue
		proc_entry = int(proc_entry)
		argv = await(get_argv(sess, proc_entry))
		if argv and name_bytes in argv[0]:
			return proc_entry
	raise FileNotFoundError

@dataclass
class MapEntry:
	start: int
	end: int
	perms: str # TODO parse into something else?
	offset: int
	name: str

async def get_maps(sess: BackdClientSession, pid: int) -> List[MapEntry]:
	entries = []
	maps = await read_file(sess, f"/proc/{pid}/maps")
	for line in maps.split(b"\n")[:-1]:
		parts = re.match(r"^([0-9a-f]+)-([0-9a-f]+) (....) ([0-9a-f]+) ..:.. [0-9]+\s+(.*)", line.decode())
		start, end, perms, offset, name = parts.groups()
		entry = MapEntry(
			start=int(start, 16),
			end=int(end, 16),
			perms=perms,
			offset=int(offset, 16),
			name=name
		)
		entries.append(entry)
	return entries

# requires an already-open /proc/pid/mem fd
async def peek(sess: BackdClientSession, memfd: int, addr: int, length: int) -> Optional[bytes]:
	await lseek(sess, memfd, addr)
	return await readn(sess, memfd, length)

async def dump_maps(sess: BackdClientSession, pid: int, maps: List[MapEntry], destdir: str):
	memfd = await sys_open(sess, f"/proc/{pid}/mem")
	for thismap in maps:
		print(thismap)
		length = thismap.end - thismap.start
		if length > 0x100000 * 100: # skip big mappings
			continue
		data = await peek(sess, memfd, thismap.start, length)
		if not data:
			#print("FAILED", map)
			continue
		with open(f"{destdir}/{thismap.start:016x}-{thismap.end:x}_{thismap.perms}_{thismap.offset:x}_{thismap.name.replace('/', '-')}", "wb") as outf:
			outf.write(data)
	await sys_close(sess, memfd)
	
