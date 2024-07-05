import re
from typing import List

from core import BackdClientSession
from fs import listdir, read_file
from dataclasses import dataclass

async def pgrep(sess: BackdClientSession, name: str) -> int:
	name_bytes = name.encode()
	proc_entries = await listdir(sess, "/proc")
	for proc_entry in proc_entries:
		if not proc_entry.isdecimal():
			continue
		cmdline = await read_file(sess, f"/proc/{proc_entry}/cmdline")
		if cmdline is None:
			continue
		argv = cmdline.split(b"\x00")
		if name_bytes in argv[0]:
			return int(proc_entry)
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
