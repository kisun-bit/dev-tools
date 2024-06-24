# Copyright (C) 2011 Paul Bolle <pebolle@tiscali.nl>. All rights reserved.
#
# Based on LVM2's library code, which mostly is
# Copyright (C) [...] Sistina Software, Inc. All rights reserved.
# Copyright (C) [...] Red Hat, Inc. All rights reserved.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU Lesser General Public License v.2.1.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

import sys
import struct


#            "\040\114\126\115\062\040\170\133\065\101\045\162\060\116\052\076"
FMTT_MAGIC = " LVM2 x[5A%r0N*>"   
FMTT_VERSION = 1
LABEL_ID = "LABELONE"
LVM2_LABEL = "LVM2 001"
MDA_HEADER_SIZE = 512


indent = "    "


# LVM2.2.02.79:lib/misc/crc.c:_calc_crc_old()
INITIAL_CRC = 0xf597a6cf

def _calc_crc(buf, crc=INITIAL_CRC):
    crctab = [0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
              0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
              0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
              0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c]
    i = 0
    while i < len(buf):
        crc ^= ord(buf[i])
        crc = (crc >> 4) ^ crctab[crc & 0xf]
        crc = (crc >> 4) ^ crctab[crc & 0xf]
        i += 1
    return crc;


def _format_mda_line(line, level):
    return _format_val("%s%s" % (indent * level, line))


# Indent metadata by its level of open braces and brackets
def _format_mda(metadata):
    braces = 0
    brackets = 0
    ret = ""

    lines = metadata.split('\n')
    for line in lines:
        if line == '\000':
            break

        # This seems to be the cleanest way to write this. It assumes
        # braces and brackets open and close only at the end of a line.
        if line.endswith('{'):
            ret = "".join((ret, _format_mda_line(line, braces + brackets)))
            braces += 1
        elif line.endswith('['):
            ret = "".join((ret, _format_mda_line(line, braces + brackets)))
            brackets += 1
        elif line.endswith('}'):
            if braces > 0:
                braces -= 1
            ret = "".join((ret, _format_mda_line(line, braces + brackets)))
        elif line.endswith(']'):
            if brackets > 0:
                brackets -= 1
            ret = "".join((ret, _format_mda_line(line, braces + brackets)))
        else:
            ret = "".join((ret, _format_mda_line(line, braces + brackets)))

    return ret


def _format_uuid(uuid):
    return _format_val("%s-%s-%s-%s-%s-%s-%s" % (uuid[  : 6], uuid[ 6:10],
                       uuid[10:14], uuid[14:18], uuid[18:22], uuid[22:26],
                       uuid[26:  ]))


def _format_hex(val):
    return "%s0x%-16x\n" % (indent, val)


def _format_crc(val):
    return "%s0x%08x\n" % (indent, val)


def _format_val(val):
    return "%s%s\n" % (indent, val)


def _format_offset_tag(offset, tag):
    return "0x%08x (%s):\n" % (offset, tag)


def _format((offset_tags_val)):
    ot = _format_offset_tag(offset_tags_val[0],
                            ".".join(offset_tags_val[1]))
    val = offset_tags_val[2]
    field = offset_tags_val[1][1]
    if field == "crc" or field.endswith("checksum"):
        v = _format_crc(val)
    elif field.endswith(("offset", "size", "start")):
        v = _format_hex(val)
    elif field == "uuid":
        v = _format_uuid(val)
    elif field == "value":
        v = _format_mda(val)
    else:
        v = _format_val(val)
    return "".join((ot, v))


def _setattr(cls, cstruct, fld, off=-1, val=None):
    setattr(cls, fld, [off, (cstruct, fld), val])


def _init_attrs(cls, fields=None):
    if not fields:
        fields = cls.fields
    for fld in fields: 
        _setattr(cls, cls.cstruct, fld, -1, None)


class _LabelHeader():
    '''Locate and parse a physical volume's label.'''
    cstruct = "label_header"
    fields = ["id", "sector", "crc", "offset", "type"]

    def __init__(self, fp):
        _init_attrs(self)

        fp.seek(0, 0)
        # the label_header can be found in the first 4 sectors of the device
        # (generally in sector 1, ie just after the MBR or volume boot sector)
        scan = 0
        while True:
            if scan > 3:
                return False
            read = fp.read(0x200)
            if len(read) != 0x200:
                return False
            if self._search_label(read, scan):
                break
            scan += 1

    def __str__(self):
        fields = [_format(getattr(self, f)) for f in self.fields]
        return "".join(fields)

    def _search_label(self, header, scan):
            if header[0:8] != LABEL_ID:
                return False
            _setattr(self, self.cstruct, "id", scan * 0x200, LABEL_ID)

            sector = struct.unpack("<Q", header[8:16])[0]
            if sector != scan:
                sys.stderr.write("sector: %d != %d\n", sector, scan)
                return False
            _setattr(self, self.cstruct, "sector", scan * 0x200 + 8, sector)

            crc = struct.unpack("<L", header[16:20])[0]
            calc = _calc_crc(header[20:])
            if calc != crc:
                sys.stderr.write("crc: %d != %d\n", calc, crc)
                return False
            _setattr(self, self.cstruct, "crc", scan * 0x200 + 16, crc)

            # offset == 0x20
            offset = struct.unpack("<L", header[20:24])[0]
            _setattr(self, self.cstruct, "offset", scan * 0x200 + 20, offset)

            if header[24:32] != LVM2_LABEL:
                sys.stderr.write("type %s != %s\n", header[24:32], LVM2_LABEL)
                return False
            _setattr(self, self.cstruct, "type", scan * 0x200 + 24, LVM2_LABEL)

            self._offset = scan * 0x200

            return True


class _DiskAreas():
    '''Parse an offset/size list (as referenced to by pv_header.disk_area)'''
    # cstruct is a misnomer here, and fields is unused 
    cstruct = None
    fields = ["offset", "size"]

    def __init__(self, area, fp, off):
        self.cstruct = area
        self.disk_locn = []
        fp.seek(off, 0)
        i = 0
        while True:
            read = fp.read(16)
            if len(read) < 16:
                break
            offset = struct.unpack("<Q", read[:8])[0]
            size = struct.unpack("<Q", read[8:16])[0]
            if offset == 0 and size == 0:
                break
            self.disk_locn.append((off + i, offset, size))
            i += 16

    def __len__(self):
        return len(self.disk_locn)

    def __getitem__(self, item):
        return self.disk_locn[item]


class _PvHeader():
    '''Parse a pv_header'''
    cstruct = "pv_header"
    fields = ["uuid", "device_size", "disk_areas"]

    def __init__(self, fp, lh):
        _init_attrs(self, self.fields[:-1])
        _setattr(self, self.cstruct, self.fields[-1], -1, [None, None])

        offset = lh._offset + getattr(lh, "offset")[2]
        fp.seek(offset, 0)
        read = fp.read(0x200 - getattr(lh, "offset")[2])

        uuid = read[:32]
        _setattr(self, self.cstruct, "uuid", offset, uuid)

        device_size = struct.unpack("<Q", read[32:40])[0]
        _setattr(self, self.cstruct, "device_size", offset + 32, device_size)
        
        _setattr(self, self.cstruct, "disk_areas", offset + 40)
        das = _DiskAreas("da", fp, offset + 40)
        mdas = _DiskAreas("mda", fp, offset + 40 + len(das) * 16 + 16)
        for areas in (das, mdas):
            for i in range(len(areas)):
                attr = "disk_areas." + areas.cstruct + str(i) + ".offset"
                self.fields.append(attr)
                _setattr(self, self.cstruct, attr, areas[i][0], areas[i][1])
                attr = "disk_areas." + areas.cstruct + str(i) + ".size"
                self.fields.append(attr)
                _setattr(self, self.cstruct, attr, areas[i][0] + 8, areas[i][2])

    def __str__(self):
        fields = [_format(getattr(self, f)) for f in self.fields if
                f != "disk_areas"]
        return "".join(fields)


class _RawLocns():
    '''Parse a list of raw_locns (as referenced to by mda_header.raw_locns)'''
    cstruct = "raw_locns"
    fields = ["offset", "size", "checksum", "flags"]

    def __init__(self, fp, off):
        self.raw_locns = []
        fp.seek(off, 0)
        i = 0
        while True:
            read = fp.read(24)
            if len(read) < 24:
                break
            offset = struct.unpack("<Q", read[:8])[0]
            size = struct.unpack("<Q", read[8:16])[0]
            checksum = struct.unpack("<L", read[16:20])[0]
            flags = struct.unpack("<L", read[20:24])[0]
            if offset == 0 and size == 0 and checksum == 0 and flags == 0:
                break
            self.raw_locns.append((off + i, offset, size, checksum, flags))
            i += 24

    def __len__(self):
        return len(self.raw_locns)

    def __getitem__(self, item):
        return self.raw_locns[item]


class _MdaHeader():
    '''Parse a mda_header'''
    cstruct = "mda_header"
    fields = ["checksum", "magic", "version", "start", "size", "raw_locns"]

    def __init__(self, fp, offset, size):
        _init_attrs(self)

        fp.seek(offset, 0)

        header = fp.read(MDA_HEADER_SIZE)
        if len(header) != MDA_HEADER_SIZE:
            raise ValueError

        checksum = struct.unpack("<L", header[:4])[0]
        calc = _calc_crc(header[4:])
        if calc != checksum:
            sys.stderr.write("crc: %d! = %d\n" % (calc, checksum))
            return
        _setattr(self, self.cstruct, "checksum", offset, checksum)
        
        magic = header[4:20]
        if magic != FMTT_MAGIC:
            sys.stderr.write("magic = %d!\n", magic)
            return
        _setattr(self, self.cstruct, "magic", offset + 4, FMTT_MAGIC)

        version = struct.unpack("<L", header[20:24])[0]
        if version != FMTT_VERSION:
            sys.stderr.write("version = %d!\n", version)
            return
        _setattr(self, self.cstruct, "version", offset + 20, version)

        start = struct.unpack("<Q", header[24:32])[0]
        if start != offset:
            sys.stderr.write("start: %d!= %d\n", start, offset)
            return
        _setattr(self, self.cstruct, "start", offset + 24, start)

        size = struct.unpack("<Q", header[32:40])[0]
        _setattr(self, self.cstruct, "size", offset + 32, size)

        _setattr(self, self.cstruct, "raw_locns", offset + 40)
        raw_locns = _RawLocns(fp, offset + 40)
        for i in range(len(raw_locns)):
            attr = raw_locns.cstruct + str(i) + ".offset"
            self.fields.append(attr)
            _setattr(self, self.cstruct, attr, raw_locns[i][0], raw_locns[i][1])
            attr = raw_locns.cstruct + str(i) + ".size"
            self.fields.append(attr)
            _setattr(self, self.cstruct, attr, raw_locns[i][0] + 8,
                     raw_locns[i][2])
            attr = raw_locns.cstruct + str(i) + ".checksum"
            self.fields.append(attr)
            _setattr(self, self.cstruct, attr, raw_locns[i][0] + 16,
                     raw_locns[i][3])
            attr = raw_locns.cstruct + str(i) + ".flags"
            self.fields.append(attr)
            _setattr(self, self.cstruct, attr, raw_locns[i][0] + 20,
                     raw_locns[i][4])

    def __str__(self):
        fields = [_format(getattr(self, f)) for f in self.fields if
                f != "raw_locns"]
        return "".join(fields)


class _Metadata():
    '''Copy the actual metadata from disk and checksum it'''
    # Made up identifiers. Haven't tried to parse the relevant code ...
    cstruct = "metadata"
    fields = ["value"]

    def __init__(self, fp, start, size, checksum):
        _init_attrs(self)

        fp.seek(start)
        metadata = fp.read(size)
        calc = _calc_crc(metadata)
        if calc != checksum:
            sys.stderr.write("crc: %d != %d\n" % (calc, checksum))
        else:
            _setattr(self, self.cstruct, "value", start, metadata)

    def __str__(self):
        fields = [_format(getattr(self, f)) for f in self.fields]
        return "".join(fields)

 
class PV():
    '''Dissect an LVM2 physical volume's metadata

    Example usage:
        >>> my_pv = PV()
        >>> my_pv.open(<path>)
        >>> print my_pv
        >>> my_pv.close()'''

    def __init__(self):
        self._fp = None
        self._lh = None
        self._ph = None
        self._mhs = []
        self._metadatas = []

    def __str__(self):
        mhs = "".join([str(m) for m in self._mhs])
        metadatas = "".join([str(m) for m in self._metadatas])
        return "".join([str(self._lh), str(self._ph), mhs, metadatas])

    def open(self, path):
        '''Open a physical volume and (try to) parse its metadata'''
        self._fp = open(path)
        self._lh = _LabelHeader(self._fp)
        if self._lh.id[2] == None:
            return
        self._ph = _PvHeader(self._fp, self._lh)

        # Note that we only parse the metadata
        mdas = {}
        for attr in dir(self._ph):
            if attr.startswith("disk_areas.mda"):
                (index, attribute) = attr[14:].split('.')
                if int(index) not in mdas:
                    mdas[int(index)] = [None, None]
                if attribute == "offset":
                    mdas[int(index)][0] = getattr(self._ph, attr)[2]
                else:
                    # attribute == "size"
                    mdas[int(index)][1] = getattr(self._ph, attr)[2]
        for mda in sorted(mdas):
            self._mhs.append(_MdaHeader(self._fp, mdas[mda][0], mdas[mda][1]))

        for mhs in self._mhs:
            raw_locns = {}
            for attr in dir(mhs):
                if attr == "raw_locns":
                    continue
                if attr.startswith("raw_locns"):
                    (index, attribute) = attr[9:].split('.')
                    if int(index) not in raw_locns:
                        raw_locns[int(index)] = [None, None, None, None]
                    if attribute == "offset":
                        raw_locns[int(index)][0] = getattr(mhs, attr)[2]
                    elif attribute == "size":
                        raw_locns[int(index)][1] = getattr(mhs, attr)[2]
                    elif attribute == "checksum": 
                        raw_locns[int(index)][2] = getattr(mhs, attr)[2]
                    else:
                        # attribute == "flags"
                        raw_locns[int(index)][3] = getattr(mhs, attr)[2]
            start = getattr(mhs, "start")[2]
            for raw_locn in sorted(raw_locns):
                self._metadatas.append(_Metadata(self._fp,
                                                 start +
                                                     raw_locns[raw_locn][0],
                                                 raw_locns[raw_locn][1],
                                                 raw_locns[raw_locn][2]))

    def close(self):
        '''Close a PV instance's file object and similar cleaning up'''
        if self._fp:
            self._fp.close()
        self._fp = None
        self._lh = None
        self._ph = None
        self._mhs = []
        self._metadatas = []