from modules import utils
from modules.debugged_process import *
from modules.disassembler import *
from modules.pe import *
from modules.process import *


class FileInformation(object):
    def __init__(self, project):
        self.__project = project
        self._md5 = None
        self._sha1 = None
        self._sha256 = None
        self._signed = None
        self._signed_reason = None
        self._version_info = None

    def __hash__(self):
        hs = utils.hash_mem(self.__project.raw)
        self._md5 = hs['md5']
        self._sha1 = hs['sha1']
        self._sha256 = hs['sha256']

    @property
    def signed(self):
        if self._signed is None:
            self._signed = check_signature(self.__project.binary_path)
            if self._signed != 0:
                self._signed_reason = FormatError(self._signed)
        return self._signed == 0

    @property
    def md5(self):
        if self._md5 is None:
            self.__hash__()
        return self._md5

    @property
    def sha1(self):
        if self._sha1 is None:
            self.__hash__()
        return self._sha1

    @property
    def sha256(self):
        if self._sha256 is None:
            self.__hash__()
        return self._sha256

    @property
    def name(self):
        return os.path.basename(self.__project.binary_fullpath)

    @property
    def size(self):
        return len(self.__project.raw)

    @property
    def creation(self):
        return datetime.datetime.fromtimestamp(
            os.path.getctime(self.__project.binary_path))

    @property
    def modification(self):
        return datetime.datetime.fromtimestamp(
            os.path.getmtime(self.__project.binary_path))

    @property
    def access(self):
        return datetime.datetime.fromtimestamp(
            os.path.getatime(self.__project.binary_path))

    @property
    def version_info(self):
        if self._version_info is None:
            f_info = self.__project.pe.helper.file_info
            if f_info is not None:
                self._version_info = f_info[0].StringTable[0].entries
        return self._version_info

    def __str__(self):
        file = "\n".join(
            ["------------------- File info -------------------", "",
             "[+] Name              : %s" % os.path.basename(self.__project.binary_fullpath),
             "[+] Timestamp         : %s" % self.__project.pe.helper.timestamp,
             "[+] Size              : %s" % utils.humansize(len(self.__project.raw)),
             "[+] Creation date     : %s" % datetime.datetime.fromtimestamp(
                 os.path.getctime(self.__project.binary_path)),
             "[+] Last modification : %s" % datetime.datetime.fromtimestamp(
                 os.path.getmtime(self.__project.binary_path)),
             "[+] Last access       : %s" % datetime.datetime.fromtimestamp(
                 os.path.getatime(self.__project.binary_path))])

        hashes = "\n".join(
            ["-------------------- Hashes --------------------", "",
             "[+] MD5          : %s" % self.md5,
             "[+] SHA1         : %s" % self.sha1,
             "[+] SHA256       : %s" % self.sha256])

        signature = "\n".join(
            ["------------------ Signature -----------------", "",
             "[+] Signature    : %s" % ("Valid" if self.signed else "Invalid"),
             "[+] Reason       : %s" % format_error(self.signed)])

        props = [b'Comments', b'InternalName', b'ProductName', b'CompanyName', b'LegalCopyright', b'ProductVersion',
                 b'FileDescription', b'LegalTrademarks', b'PrivateBuild', b'FileVersion', b'OriginalFilename',
                 b'SpecialBuild']

        if self.version_info is not None:
            version_info_str = ["---------------- Version info -----------------", ""]
            for prop in sorted(props):
                if prop in self.version_info:
                    version_info_str.append("[+] %-18s        : %s" % (prop.decode(), self.version_info[prop].decode()))
            versions = "\n".join(version_info_str)

            return "\n\n".join([file, hashes, versions, signature, ""])
        else:
            return "\n\n".join([file, hashes, signature, ""])


class Project:
    def __init__(self, binary_path):
        self._binary_path = binary_path
        self._pe = None
        self._functions = None
        self._file_info = None
        self._raw = None
        self._disassembler = None
        self._disassembler_persistent = None
        try:
            f = open(self._binary_path, "rb")
            self._raw = f.read()
            f.close()
        except FileNotFoundError as e:
            self._raw = None
            raise e

    @property
    def binary_path(self):
        return self._binary_path

    @property
    def binary_fullpath(self):
        return os.path.abspath(self._binary_path)

    @property
    def raw(self):
        return self._raw

    @property
    def pe(self):
        if self._pe is None:
            if self._raw is not None:
                try:
                    self._pe = PE(self._raw)
                except PEFormatError as e:
                    self._pe = None
                    raise e
        return self._pe

    @property
    def file_info(self):
        if self._file_info is None:
            if self._raw is not None:
                try:
                    self._file_info = FileInformation(self)
                except Exception as e:
                    self._file_info = None
                    raise e
        return self._file_info

    def find_strings(self, min_length=4, max_length=256):
        strings = []
        if self._raw is not None:
            pattern = b"[^\x00-\x1F\x7F-\xFF]{" + str(min_length).encode() + b"," + str(max_length).encode() + b"}"
            strings = re.findall(pattern, self._raw)
        return list(map(lambda x: x.decode(), strings))

    def find_xored_strings(self, min_length=8, max_length=20, key=None):
        strings = set()
        if self._raw is not None:
            pattern = b"[^\x00-\x1F\x7F-\xFF]{" + str(min_length).encode() + b"," + str(max_length).encode() + b"}"
            for key in range(1, 256):
                s = re.findall(pattern, utils.xor(self._raw, key))
                for st in s:
                    strings.add(st.decode())
        return strings

    @property
    def blocks(self):
        if self._disassembler_persistent is not None:
            return self._disassembler_persistent.block_list
        else:
            log_warn("Use disass_all command before blocks")

    @property
    def functions(self):
        if self._disassembler_persistent is not None:
            return self._disassembler_persistent.function_list
        else:
            log_warn("Use disass_all command before functions")

    def disass_all(self):
        if self.pe is not None:
            try:
                self._disassembler_persistent = RecursiveDisassembler(self)
            except Exception as e:
                raise e

    def disass(self, begin=None, end=None, size=None):
        if self.pe is not None:
            if self._disassembler is None:
                self._disassembler = get_raw_disassembler(self.pe.helper.architecture)
            if begin is None:
                begin = self._pe.helper.entry_point
            if end is None:
                if size is None:
                    size = 0x64
                end = begin + size
            else:
                if size is not None:
                    if begin + size != end:
                        raise Exception("Disassembling: begin + size != end")
            if begin >= end:
                raise Exception("Disassembling: begin >= end")
            for i in self._disassembler.disasm(bytes(self.pe.helper.mapped[begin:end]), begin):
                print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
            print()

    def run_suspended(self, arguments=None, flags=0):
        p = Process(self.binary_path)
        p.run(arguments, flags + CreationFlag.CREATE_SUSPENDED.value)
        return p

    def run(self, arguments=None, flags=0):
        p = Process(self.binary_path)
        p.run(arguments, flags)
        return p

    def debug(self):
        return DebuggedProcess(self.binary_path)
