import zipfile
from typing import Dict

def get_file_offsets(zip_path: str) -> Dict[str, int]:
	offsets = {} # path -> offset
	with open("RabbitLauncher.apk", "rb") as f:
		zf = zipfile.ZipFile(f)

		for zinfo in zf.infolist():
			f.seek(zinfo.header_offset + 26)
			namelen = int.from_bytes(f.read(2), "little")
			extralen = int.from_bytes(f.read(2), "little")
			file_offset = zinfo.header_offset + 30 + namelen + extralen
			offsets[zinfo.filename] = file_offset

	return offsets
