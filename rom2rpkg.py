#!/usr/bin/env python3
"""
v1.0.0 - 27/09/2026
rom2rpkg.py — extract an EKA1 ROM's embedded Z: filesystem and pack it
straight into an EKA2L1-compatible .rpkg (v1, "RPKG" header).

Parsing logic ported from EKA2L1's own source:
  src/emu/loader/src/rom.cpp                 (read_rom_header / read_rom_dir / read_rom_entry)
  src/emu/system/src/installation/rpkg.cpp   (install_rpkg reader — this is what
                                               the .rpkg writer here was verified against)

Only handles EKA1 ROMs (rom_base == 0x50000000), i.e. header.rom_base check in
read_rom_header's EKA1 branch. For EKA2 ROMs the header layout differs (more
fields) — ask if you need that branch too, it's a straightforward extension.

IMPORTANT: EKA2L1 decides whether a ROM needs an *external* RPKG by checking for
six "device naming" files inside the ROM's own Z: tree (see
device_naming_files() in src/emu/system/src/software.cpp):
    resource\\versions\\product.txt
    resource\\versions\\sw.txt
    resource\\versions\\langsw.txt
    system\\versions\\sw.txt
    system\\versions\\langsw.txt
    system\\install\\sonyericssonp90xplatform.sis
If NONE of these are present in your ROM (this script tells you), packing an
RPKG from the ROM's own files is necessary but not sufficient for automatic
"Install device" — EKA2L1 still won't be able to determine the manufacturer/
firmcode/model from it. You'd need to merge in the real naming file(s) from an
actual device Z: dump (e.g. via Dumberdore / rpkgmaker) for install to succeed;
the RPKG this script produces is otherwise a complete, correctly-formatted
container of everything embedded in the ROM.

Usage:
    python3 rom2rpkg.py ROM-0x50000000-0.dmp output.rpkg
"""
import struct
import sys

FILE_ATTRIB_DIR = 0x10

NAMING_FILES = [
    "resource\\versions\\product.txt",
    "resource\\versions\\sw.txt",
    "resource\\versions\\langsw.txt",
    "system\\versions\\sw.txt",
    "system\\versions\\langsw.txt",
    "system\\install\\sonyericssonp90xplatform.sis",
]


class Cursor:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def seek(self, pos):
        self.pos = pos

    def tell(self):
        return self.pos

    def read(self, n):
        b = self.data[self.pos:self.pos + n]
        self.pos += n
        return b

    def u32(self):
        return struct.unpack_from("<I", self.read(4))[0]

    def u8(self):
        return self.read(1)[0]


def read_rom_header(c: Cursor):
    hdr = {}
    c.read(124)  # jump table
    hdr['restart_vector'] = c.u32()
    hdr['major'] = c.u8()
    hdr['minor'] = c.u8()
    hdr['build'] = struct.unpack_from("<H", c.read(2))[0]
    hdr['time'] = struct.unpack_from("<q", c.read(8))[0]
    hdr['rom_base'] = c.u32()
    hdr['rom_size'] = c.u32()
    hdr['rom_root_dir_list'] = c.u32()
    hdr['kern_data_address'] = c.u32()
    hdr['kern_limit'] = c.u32()
    hdr['primary_file'] = c.u32()
    hdr['secondary_file'] = c.u32()
    hdr['checksum'] = c.u32()
    hdr['lang'] = struct.unpack_from("<q", c.read(8))[0]
    hdr['hardware'] = c.u32()
    hdr['size_x'] = struct.unpack_from("<i", c.read(4))[0]
    hdr['size_y'] = struct.unpack_from("<i", c.read(4))[0]
    hdr['bpp'] = c.u32()
    hdr['rom_section_header'] = c.u32()
    hdr['total_sv_data_size'] = struct.unpack_from("<i", c.read(4))[0]
    hdr['variant_file'] = c.u32()
    hdr['extension_file'] = c.u32()
    hdr['reloc_info'] = c.u32()
    hdr['old_trace_mask'] = c.u32()
    hdr['user_data_addr'] = c.u32()
    hdr['total_user_data_size'] = struct.unpack_from("<i", c.read(4))[0]
    hdr['debug_port'] = c.u32()
    hdr['compress_type'] = c.u32()
    hdr['compress_size'] = c.u32()
    hdr['uncompress_size'] = c.u32()

    if hdr['rom_base'] != 0x50000000:
        raise ValueError(
            "This ROM's rom_base is 0x%X, not the EKA1 base 0x50000000 — "
            "it needs the EKA2 header branch, which this script doesn't implement."
            % hdr['rom_base']
        )
    return hdr


def rom_off(rom_base, lin_addr):
    return lin_addr - rom_base


def read_rom_entry(c: Cursor, rom_base, mother_subdirs):
    size = c.u32()
    addr_lin = c.u32()
    attrib = c.u8()
    name_len = c.u8()
    name = c.read(2 * name_len).decode('utf-16-le')
    entry = {'size': size, 'addr_lin': addr_lin, 'attrib': attrib, 'name': name}
    if attrib & FILE_ATTRIB_DIR:
        crr = c.tell()
        c.seek(rom_off(rom_base, addr_lin))
        d = read_rom_dir(c, rom_base)
        d['name'] = name
        mother_subdirs.append(d)
        c.seek(crr)
    return entry


def read_rom_dir(c: Cursor, rom_base):
    old_off = c.tell()
    size = c.u32()
    d = {'size': size, 'name': '', 'entries': [], 'subdirs': []}
    while c.tell() - old_off < size:
        entry = read_rom_entry(c, rom_base, d['subdirs'])
        d['entries'].append(entry)
        if c.tell() % 4 != 0:
            c.seek(c.tell() + 2)
    return d


def read_root_dir_list(c: Cursor, rom_base):
    num = c.u32()
    roots = []
    for _ in range(num):
        last_pos = c.tell()
        hw_variant = c.u32()
        addr_lin = c.u32()
        c.seek(rom_off(rom_base, addr_lin))
        d = read_rom_dir(c, rom_base)
        roots.append({'hardware_variant': hw_variant, 'dir': d})
        c.seek(last_pos)
    return roots


def load_rom(data: bytes):
    c = Cursor(data)
    hdr = read_rom_header(c)
    c.seek(rom_off(hdr['rom_base'], hdr['rom_root_dir_list']))
    roots = read_root_dir_list(c, hdr['rom_base'])
    return hdr, roots


def walk_files(dir_node, prefix="Z:"):
    for e in dir_node['entries']:
        if not (e['attrib'] & FILE_ATTRIB_DIR) and e['size'] != 0:
            yield (prefix + "\\" + e['name'], e['addr_lin'], e['size'])
    for sub in dir_node['subdirs']:
        yield from walk_files(sub, prefix + "\\" + sub['name'])


def pack_entry(path: str, data: bytes, attrib: int = 0, time_: int = 0) -> bytes:
    path_u16 = path.encode("utf-16-le")
    path_len = len(path_u16) // 2
    out = struct.pack("<QQQ", attrib, time_, path_len)
    out += path_u16
    out += struct.pack("<Q", len(data))
    out += data
    return out


def write_rpkg_v1(out_path: str, entries, major=0, minor=0, build=0):
    entries = list(entries)
    with open(out_path, "wb") as f:
        for ch in b"RPKG":
            f.write(struct.pack("<I", ch))
        f.write(struct.pack("<BBHI", major, minor, build, len(entries)))
        for path, data in entries:
            f.write(pack_entry(path, data))


def make_product_txt_entry(manufacturer: str, product: str, model: str) -> tuple:
    """
    Builds a synthetic Z:\\resource\\versions\\product.txt entry.
    This is the FIRST method EKA2L1 tries in determine_rpkg_product_info()
    (src/emu/system/src/software.cpp) — a simple key=value INI, no section
    header needed. Faking this file is enough to fix "product info could not
    be determined" when the real device-naming files aren't in the ROM.
    """
    content = ("Manufacturer=%s\r\nProduct=%s\r\nModel=%s\r\n" % (manufacturer, product, model)).encode("ascii")
    return ("Z:\\resource\\versions\\product.txt", content)


def make_sonyericsson_uid_marker_entry() -> tuple:
    """
    determine_rpkg_product_info() (src/emu/system/src/software.cpp) special-cases
    Z:\\system\\install\\sonyericssonp90xplatform.sis: if it exists, product info is
    read from the REAL machine UID baked into the ROM's own hal.dll (P800 ->
    0x101F408B, P900 -> 0x101FB2AE), instead of needing a resource\\versions\\*.txt
    file. Only existence is checked, not content, and real P800 dumps ship the file
    as "...P80x..." rather than this exact "...P90x..." name EKA2L1 looks for -
    hence this marker. Use this instead of make_product_txt_entry() whenever the ROM
    is a genuine Sony Ericsson UIQ dump: it reports the true model instead of a guess.
    """
    return ("Z:\\system\\install\\sonyericssonp90xplatform.sis", b"")


def make_uiq_platform_marker_entry() -> tuple:
    """
    determine_rpkg_symbian_version() (src/emu/system/src/software.cpp) checks for
    Z:\\system\\install\\uiq21platform.sis FIRST, before anything else, and returns
    epocver::epoc70 immediately if it exists. The Qt frontend labels epoc70 as
    "UIQ - 7.0" (src/emu/qt/src/utils.cpp). Content is never read — only existence
    matters — so an empty file is enough.
    """
    return ("Z:\\system\\install\\uiq21platform.sis", b"")


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 rom2rpkg.py <rom_dump_file> <output.rpkg> "
              "[manufacturer product model] [--uiq] [--se-uid]")
        print("  --se-uid : genuine Sony Ericsson UIQ dump -> identify via real hal.dll UID")
        print("             instead of a guessed manufacturer/product/model")
        sys.exit(1)

    rom_path, out_path = sys.argv[1], sys.argv[2]
    rest = sys.argv[3:]
    want_uiq = "--uiq" in rest
    want_se_uid = "--se-uid" in rest
    rest = [a for a in rest if a not in ("--uiq", "--se-uid")]
    synthetic_product = rest[:3] if len(rest) >= 3 else None
    data = open(rom_path, "rb").read()
    hdr, roots = load_rom(data)

    print("rom_base=0x%X rom_size=0x%X root_dirs=%d" % (hdr['rom_base'], hdr['rom_size'], len(roots)))

    entries = []
    for r in roots:
        for path, addr_lin, size in walk_files(r['dir']):
            file_off = addr_lin - hdr['rom_base']
            entries.append((path, data[file_off:file_off + size]))

    print("Extracted %d files from ROM's embedded Z: tree." % len(entries))

    lower_paths = [p.lower().replace("z:\\", "") for p, _ in entries]
    found_naming = [n for n in NAMING_FILES if n.lower() in lower_paths]
    if not found_naming:
        print("\nWARNING: none of the device-naming files were found inside this ROM:")
        for n in NAMING_FILES:
            print("   -", n)
        print("EKA2L1 will still ask for a separate RPKG to identify the device.")
        print("The .rpkg below is a valid, complete package of the ROM's own files,")
        print("but you'll need to merge in the real naming file(s) from a device")
        print("dump for automatic 'Install device' to succeed.\n")
    else:
        print("Found naming file(s):", found_naming)

    if synthetic_product:
        manufacturer, product, model = synthetic_product
        entries.append(make_product_txt_entry(manufacturer, product, model))
        print("Injected synthetic product.txt -> Manufacturer=%s Product=%s Model=%s"
              % (manufacturer, product, model))

    if want_se_uid:
        entries.append(make_sonyericsson_uid_marker_entry())
        print("Injected sonyericssonp90xplatform.sis marker -> device identity will be read "
              "from this ROM's own hal.dll machine UID")

    if want_uiq:
        entries.append(make_uiq_platform_marker_entry())
        print("Injected uiq21platform.sis marker -> Symbian version will report as UIQ - 7.0")

    write_rpkg_v1(out_path, entries)
    print("Wrote", out_path)


if __name__ == "__main__":
    main()
