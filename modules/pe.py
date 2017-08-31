import datetime
import re
import struct

import libs.ordlookup as ordlookup
import libs.pefile as pefile
from modules.constants import ImageDirectory, BinaryType


class PEFormatError(Exception):
    pass


class MappedPE(object):
    def __init__(self, pe):
        self._base = pe.OPTIONAL_HEADER.ImageBase
        self._mapped_data = pe.get_memory_mapped_image(ImageBase=self._base)
        self._vitual_size_max = 0x7fffffff if pe.OPTIONAL_HEADER.Magic == 0x10b else 0x7ffffffffff

    def __getitem__(self, item):
        left = 0
        if isinstance(item, int):
            if item < self._base:
                raise IndexError('Address is before image base')
            if item >= self._vitual_size_max:
                raise IndexError('Address is after max virtual memory size')
            if item >= self._base + len(self._mapped_data):
                return b'\0'
            return self._mapped_data[item - self._base]
        elif isinstance(item, slice):
            start, stop, step = item.start, item.stop, item.step
            if start is not None:
                if start < self._base:
                    raise IndexError('Address 0x%08x is before image base 0x%08x' % (start, self._base))
            if stop is not None:
                if stop >= self._vitual_size_max:
                    raise IndexError('Address is after max virtual memory size')
                if stop > self._base + len(self._mapped_data):
                    left = stop - self._base + len(self._mapped_data)
                    stop = self._base + len(self._mapped_data)

            return self._mapped_data[slice(start - self._base if start is not None else None,
                                           stop - self._base if stop is not None else None,
                                           step)] + b'\0' * left
        else:
            raise TypeError('Index must be int, not {}'.format(type(item).__name__))

    def __setitem__(self, key, value):
        raise PermissionError('Mapped PE cannot be modified')

    def __delitem__(self, key):
        raise PermissionError('Mapped PE cannot be modified')


class PEHelper(object):
    def __init__(self, pefile_instance):
        self._pefile = pefile_instance
        self._imports = None
        self._delay_imports = None
        self._mapped = None
        self._strings = None

    @property
    def image_base(self):
        return self._pefile.OPTIONAL_HEADER.ImageBase

    @property
    def entry_point(self):
        return self._pefile.OPTIONAL_HEADER.AddressOfEntryPoint + self._pefile.OPTIONAL_HEADER.ImageBase

    @property
    def timestamp(self):
        return datetime.datetime.fromtimestamp(self._pefile.FILE_HEADER.TimeDateStamp)

    @property
    def nb_of_sections(self):
        return self._pefile.FILE_HEADER.NumberOfSections

    def get_section_from_rva(self, rva):
        return self._pefile.get_section_by_rva(rva)

    @property
    def tls_callbacks(self):
        cbs = []
        if hasattr(self._pefile, 'DIRECTORY_ENTRY_TLS'):
            cb_entry = self._pefile.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - self.image_base
            section = self.get_section_from_rva(cb_entry)
            cb = struct.unpack("<I", section.get_data(start=cb_entry, length=4))[0]
            while cb != 0:
                cbs.append(cb)
                cb_entry += 4
                cb = struct.unpack("<I", section.get_data(start=cb_entry, length=4))[0]
        return cbs

    @property
    def architecture(self):
        if self._pefile.OPTIONAL_HEADER.Magic == 0x10b:
            return BinaryType.SCS_32BIT_BINARY.value
        elif self._pefile.OPTIONAL_HEADER.Magic == 0x20b:
            return BinaryType.SCS_64BIT_BINARY.value
        elif self._pefile.OPTIONAL_HEADER.Magic == 0x107:
            return BinaryType.SCS_DOS_BINARY.value
        else:
            return None

    @property
    def imports(self):
        if self._imports is None:
            self._imports = dict()
            if hasattr(self._pefile, "DIRECTORY_ENTRY_IMPORT"):
                for entry in self._pefile.DIRECTORY_ENTRY_IMPORT:
                    libname = entry.dll.decode().lower()
                    functions = dict()
                    for imp in entry.imports:
                        if imp.import_by_ordinal is True:
                            funcname = ordlookup.ordLookup(entry.dll.lower(), imp.ordinal, make_name=True)
                            if not funcname:
                                raise Exception("Unable to look up ordinal %s:%04x" % (entry.dll, imp.ordinal))
                        else:
                            funcname = imp.name
                        if funcname is not None:
                            functions[funcname] = imp.address
                    self._imports[libname] = functions
        return self._imports

    @property
    def delay_imports(self):
        if self._delay_imports is None:
            self._delay_imports = dict()
            if hasattr(self._pefile, "DIRECTORY_ENTRY_DELAY_IMPORT"):
                for entry in self._pefile.DIRECTORY_ENTRY_DELAY_IMPORT:
                    libname = entry.dll.decode().lower()
                    functions = dict()
                    for imp in entry.imports:
                        if imp.import_by_ordinal is True:
                            funcname = ordlookup.ordLookup(entry.dll.lower(), imp.ordinal, make_name=True)
                            if not funcname:
                                raise Exception("Unable to look up ordinal %s:%04x" % (entry.dll, imp.ordinal))
                        else:
                            funcname = imp.name
                        if funcname is not None:
                            functions[funcname] = imp.address
                    self._delay_imports[libname] = functions
        return self._delay_imports

    @property
    def strings(self):
        if self._strings is None:
            self._strings = []
            for section in self._pefile.sections:
                if section.Characteristics & pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_READ"] and \
                                section.Characteristics & pefile.SECTION_CHARACTERISTICS[
                            "IMAGE_SCN_CNT_INITIALIZED_DATA"]:
                    self._strings.extend(re.findall(b"[^\x00-\x1F\x7F-\xFF]{4,}", section.get_data()))
        return self._strings

    @property
    def mapped(self):
        if self._mapped is None:
            self._mapped = MappedPE(self._pefile)
        return self._mapped

    @property
    def imphash(self):
        return self._pefile.get_imphash()

    @property
    def file_info(self):
        if hasattr(self._pefile, "FileInfo"):
            return self._pefile.FileInfo
        return None

    # TODO
    @property
    def signature(self):
        d = self._pefile.OPTIONAL_HEADER.DATA_DIRECTORY[ImageDirectory.IMAGE_DIRECTORY_ENTRY_SECURITY.value]
        if d.VirtualAddress and d.Size:
            offset = self._pefile.get_data(d.VirtualAddress, d.Size)
        return None


class PE(object):
    def __init__(self, data):
        ex = None
        try:
            self._pefile = pefile.PE(data=data, fast_load=False)
            self._helper = PEHelper(self._pefile)
        except pefile.PEFormatError as e:
            ex = PEFormatError(e.value)
        if ex is not None:
            raise ex

    @property
    def dos_header(self):
        return self._pefile.DOS_HEADER

    @property
    def file_header(self):
        return self._pefile.FILE_HEADER

    @property
    def optional_header(self):
        return self._pefile.OPTIONAL_HEADER

    @property
    def nt_header(self):
        return self._pefile.NT_HEADERS

    @property
    def rich_header(self):
        return self._pefile.RICH_HEADER

    @property
    def sections(self):
        return self._pefile.sections

    @property
    def data_directory(self):
        return self._pefile.OPTIONAL_HEADER.DATA_DIRECTORY

    @property
    def warnings(self):
        return self._pefile.get_warnings()

    @property
    def helper(self):
        return self._helper
