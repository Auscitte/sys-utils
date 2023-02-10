""" Enumerates WinSxS entries establishing "delta" dependencies between multiple versions of the same file

    win_read_winsxs.py is meant to assist in reverse-engineering and troubleshooting Windows updates,
    when one needs to locate succesive versions of an assembly.

    This module does not rely on manifests; instead, the assembly identities are established based
    solely on the directory names when the WinSxS folder is traversed. For each encountered file, the
    algorithm builds a sequence of its versions, checking for each sequence element (excluding the
    first one) if it can be derived from the preceeding one by applying the reverse and forward 
    differentials stored in WinSxS. Below is an example of such sequence for the file shlwapi.dll.

    shlwapi.dll: 10.0.19041.1○ ==> 10.0.19041.1706 <==> 10.0.19041.2075

    The version 10.0.19041.1 is identified as "base", which is indicated by the "○" symbol next to it. 
    In this case, the DLL revision being equal to 1, the base is indeed identified correctly;
    but in general, it is an educated guess only for we cannot determine with certainty if this is
    an RTM version or the file came with a major Windows release. Applying a forward differential to
    10.0.19041.1, we obtain 10.0.19041.1706. The version 10.0.19041.2075 is reconstructed from
    10.0.19041.1706, by a sequential application of two differentials: reverse and forward.


    :Copyright:
        Ry Auscitte 2023. This script is distributed under MIT License.

    :Authors:
        Ry Auscitte

"""

import os
import sys
import re
import glob
import time
from enum import Enum
from dataclasses import dataclass
from typing import List, Tuple, Optional


class WinSxSEntry:
    """A WinSxS assembly"""
    exp = "([^_]+)_(.*)_([0-9,a-f,A-F]+)_"\
          "([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)_"\
          "(.*)_([0-9,a-f,A-F]{16})"
    groups = [ "arch", "name", "public_token",
               "ver_major", "ver_minor", "ver_build", "ver_rev",
               "locale", "hash" ]
    ver_start_idx = groups.index("ver_major")
    ver_end_idx = groups.index("ver_rev") + 1

    dir2diff = { "f":"fwd_diff", "r": "rvs_diff", "n":"null_diff" }

    def __init__(self, name: str) -> None:
        self.fwd_diff = set()
        self.rvs_diff = set()
        self.null_diff = set()
        self.files = set()

        if m := re.match(WinSxSEntry.exp, name):
            for i in range(len(WinSxSEntry.groups)):
                self.__dict__[WinSxSEntry.groups[i]] = m.group(i + 1)
        else:
            raise ValueError(f"{name} is not a valid entry")

        path = os.path.join(WinSxS.winsxs_path, name)
        self.mod_ts = os.path.getmtime(path)
        itms = glob.glob(os.path.join(path, "*"))

        files = [ os.path.basename(itm) for itm in itms if os.path.isfile(itm) ]
        self.files.update(files)

        dirs = [ os.path.basename(itm) for itm in itms if os.path.isdir(itm) ]
        for d in dirs:
            fls = glob.glob(os.path.join(path, d, "**", "*"), recursive = True)
            idx = 1 + len(os.path.join(path, d) if d in WinSxSEntry.dir2diff else path)
            fls = [ f[idx :] for f in fls if os.path.isfile(f) ]
            if d in WinSxSEntry.dir2diff:
                self.__dict__[WinSxSEntry.dir2diff[d]].update(fls)
            else:
                self.files.update(fls)

    def _get_path(self, file_name: str, diff_type: Optional[str]) -> str:
        fn = self.folder
        nm = fn if diff_type is None else os.path.join(fn, diff_type)
        return os.path.join(WinSxS.winsxs_path, nm, file_name)

    def get_rev_path(self, file_name: str) -> str:
        return self._get_path(file_name, "r")

    def get_fwd_path(self, file_name: str) -> str:
        return self._get_path(file_name, "f")

    def get_null_path(self, file_name: str) -> str:
        return self._get_path(file_name, "n")

    def get_file_path(self, file_name: str) -> str:
        return self._get_path(file_name, None)

    def is_base(self, file: str) -> bool:
        """It is an educated guess only"""
        return (file in self.files or file in self.null_diff) and not file in self.rvs_diff

    def from_scratch(self, file: str) -> bool:
        return (file in self.files or file in self.null_diff) and not file in self.fwd_diff

    @property
    def version(self) -> str:
        return ".".join([ str(self.ver_major), str(self.ver_minor),
                          str(self.ver_build), str(self.ver_rev) ])
    @property
    def int_version(self) -> Tuple[int, int, int, int]:
        return (int(self.ver_major), int(self.ver_minor),
                int(self.ver_build), int(self.ver_rev))

    @property
    def folder(self) -> str:
        part1 = "_".join([ self.__dict__[itm] for itm in 
                          WinSxSEntry.groups[: WinSxSEntry.ver_start_idx] ])
        part3 = "_".join([ self.__dict__[itm] for itm in 
                          WinSxSEntry.groups[WinSxSEntry.ver_end_idx :] ])
        return "_".join([ part1, self.version, part3])

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.name = })"

    def __str__(self) -> str:
        return str(self.name) +\
               "\n\t files: " + str(self.files) +\
               "\n\t fwd: " + str(self.fwd_diff) +\
               "\n\t rev: " + str(self.rvs_diff) +\
               "\n\t null: " + str(self.null_diff) +\
               "\n\t arch: " + str(self.arch) +\
               "\n\t ver: " + self.version +\
               "\n\t ts: " + str(time.ctime(self.mod_ts)) +\
               "\n\t loc: " + self.locale +\
               "\n\t token: " + self.public_token +\
               "\n\t hash: " + self.hash


class Relation(Enum):
    """ A relation between two verions of the same file.
        
        ReverseForward implies that one version of the file is derived from another
        by first applying a reverse differential, thereby obtaining an intermediate (base)
        version, and then applying a forward differential to the base.
        In case of the Forward relation, a forward differential is sufficient.
    """
    Error = 0
    No = 1
    Forward = 2
    ReverseForward = 3


def apply_differential_to_file(in_file: str, diff_file: str) -> bytes:
    data = None
    with open(in_file, 'rb') as r:
        data = r.read()

    return apply_differential_to_buffer(data, diff_file)


def apply_differential_to_buffer(in_buf: bytes, diff_file: str) -> bytes:
    """ Applies the differential specified by the path ``diff_file`` to ``in_buf``.
        apply_differential_to_buffer() uses delta_patch.py from
        https://gist.github.com/wumb0/9542469e3915953f7ae02d63998d2553
    """
    import delta_patch
    from ctypes import wintypes, cast, c_ubyte

    buf = cast(in_buf, wintypes.LPVOID)
    n = len(in_buf)
    try:
        buf, n = delta_patch.apply_patchfile_to_buffer(buf, n, diff_file, False)
    except Exception as e:
        return bytes()

    # From https://docs.python.org/3/library/ctypes.html#arrays :
    # "The recommended way to create array types is by multiplying a data type
    # with a positive integer"
    out_buf = bytes((c_ubyte * n).from_address(buf))
    delta_patch.DeltaFree(buf)
    return out_buf


def check_rvsfwd_sequence(parent: WinSxSEntry, child: WinSxSEntry, file_name: str) -> Relation:
    """ Establishes a relation between ``parent`` and ``child``.
        check_rvsfwd_sequence() determines if ``child`` can be derived from ``parent``
        by applying available differentials.
    """
    if file_name in child.null_diff:
       return Relation.No

    if not file_name in child.files or\
       not file_name in parent.files:
        return Relation.Error

    if not file_name in child.fwd_diff:
        return Relation.No

    ret = Relation.No
    if file_name in parent.rvs_diff:
        ret = Relation.ReverseForward
        base_buf = apply_differential_to_file(parent.get_file_path(file_name),
                                              parent.get_rev_path(file_name))
        if len(base_buf) == 0:
            return Relation.Error

        out_buf = apply_differential_to_buffer(base_buf,
                                               child.get_fwd_path(file_name))
    else:
         ret = Relation.Forward
         out_buf = apply_differential_to_file(parent.get_file_path(file_name),
                                              child.get_fwd_path(file_name))
    if len(out_buf) == 0:
        return Relation.No

    data = None
    with open(child.get_file_path(file_name), 'rb') as r:
        data = r.read()

    return ret if data == out_buf else Relation.No


class Sequence:
    """A sequence of versions, ordered from the oldest to the latest, for a file"""
    def __init__(self, lst: List[WinSxSEntry], file: str) -> None:
        self._entries = lst
        self._file = file
        self._rels = [ Relation.Error for i in range( 2 * len(lst) - 1) ]
        for i in range(len(lst)):
            self._rels[2 * i] = lst[i].is_base(file)

        for i in range(len(lst) - 1):
            self._rels[2 * i + 1] = check_rvsfwd_sequence(lst[i], lst[i + 1], file)

    def __str__(self) -> str:
        if len(self._entries) == 0:
            return ""
        s = self._file + ": " + self._entries[0].version
        if self._rels[0]:
           s += Sequence.base_symbol

        for i in range(1, len(self._entries)):
            s += " "
            s += Sequence.rel_symbols[self._rels[2 * i - 1]]
            s += " "
            s += self._entries[i].version
            if self._rels[2 * i]:
               s += Sequence.base_symbol

        return s

    def get_relation_to_parent(self, p: int) -> Relation:
        if p >= len(self._entries) or p < 1:
            raise ValueError("Wrong Index")
        return self._rels[2 * p - 1]

    def is_base(self, n: int) -> bool:
        return self._rels[2 * n]

    base_symbol = "○"
    rel_symbols = { Relation.Error : ".=?=.",
                    Relation.No : ".=X=.",
                    Relation.Forward : "==>",
                    Relation.ReverseForward : "<==>" }


@dataclass(frozen = True, eq = True)
class WinSxSDirId:
    """Identifies a WinSxS assembly"""
    arch: str
    locale: str
    dir: str


@dataclass(frozen = True, eq = True)
class WinSxSFileId:
    """Identifies a file within the containing WinSxS assembly"""
    arch: str
    locale: str
    dir: str
    file: str


def get_top_dir(root: str, path: str) -> str:
    """Returnes the first directory in ``path`` immediately following the ``root`` prefix"""
    top = ""
    root = os.path.normcase(root)
    path = os.path.normcase(path)
    while root != path:
        s = os.path.split(path)
        assert(len(s) == 2)
        path = s[0]
        top = s[1]
    return top


def same_file_name(long_name: str, short_name: str) -> str:
    """Checks if ``long_name`` is a (partial) path to a file named ``short_name``"""
    long_name = os.path.normcase(long_name)
    short_name = os.path.normcase(short_name)
    if not long_name.endswith(short_name):
        return False
    long_name = long_name[0 : -len(short_name)]
    return len(long_name) == 0 or long_name[len(long_name) - 1] == os.sep


class WinSxS:
    """A container for WinSxS entries"""
    winsxs_path = None

    @classmethod
    def set_default_path_to_winsxs(cls):
        cls.winsxs_path = os.path.join(os.path.expandvars("%windir%"), "WinSxS")

    def __init__(self, file_name: Optional[str] = None, recursive: bool = False) -> None:
        if not WinSxS.winsxs_path:
            WinSxS.set_default_path_to_winsxs()

        if file_name:
            path = os.path.join(WinSxS.winsxs_path, "**" if recursive else "*", file_name)
            #recursive enumeration counts "/{r, n, m}/**/file_name" in as well resulting in duplicate entries
            dirs = { get_top_dir(WinSxS.winsxs_path, itm) 
                     for itm in glob.glob(path, recursive = recursive) }
        else:
            dirs = { os.path.basename(itm) for itm in glob.glob(os.path.join(WinSxS.winsxs_path, "*"))
                     if os.path.isdir(itm) }

        self._verfiles = {}
        self._verdirs = {}
        for d in dirs:
            try:
                entry = WinSxSEntry(d)
                for f in entry.files:
                    if file_name and not same_file_name(f, file_name):
                        continue
                    id = WinSxSFileId(entry.arch, entry.locale, entry.name, f)
                    if not id in self._verfiles:
                        self._verfiles[id] = []
                    self._verfiles[id].append(entry)

                id = WinSxSDirId(entry.arch, entry.locale, entry.name)
                if not id in self._verdirs:
                    self._verdirs[id] = []
                self._verdirs[id].append(entry)
            except ValueError as e:
                pass

        for _, v in self._verfiles.items():
            self._sort_entries_by_vers(v)

        for _, v  in self._verdirs.items():
            self._sort_entries_by_vers(v)

    def _sort_entries_by_vers(self, entries : List[WinSxSEntry]) -> None:
        entries.sort(key = lambda x: x.int_version + (x.mod_ts, ) )

    def check_diff_signatures(self) -> bool:
        allgood = True
        for (_, _, fn), entries in self._verfiles.items():
            for e in entries:
                if fn in e.rvs_diff:
                    allgood &= WinSxS._check_diff_signature(e.get_rev_path(fn))
                if fn in e.fwd_diff:
                    allgood &= WinSxS._check_diff_signature(e.get_fwd_path(fn))
                if fn in e.null_diff:
                    allgood &= WinSxS._check_diff_signature(e.get_null_path(fn))
        return allgood

    @staticmethod
    def _check_diff_signature(path: str) -> bool:
        with open(path, 'rb') as f:
            f.seek(4)
            data = f.read(4)
            if data != b"PA30":
                print("Unsupported file signature: ", path)
                return False
        return True

    @property
    def versioned_files(self):
        return self._verfiles

    @property
    def versioned_dirs(self):
        return self._verdirs


if __name__ == '__main__':

    #https://isaacong.me/posts/unicodeencodeerror-when-redirecting-python-output/
    sys.stdout.reconfigure(encoding = "utf-8")

    from argparse import ArgumentParser
    ap = ArgumentParser(description = "Traverse WinSxS folder to establish relations pertaining to differentail updates between various verions of the same file")
    ap.add_argument("-f", "--file", required = False, help = "a file name (or a partial path,  e.g. \"InputApp\\Assets\\KbdKeyTap.wav\")")
    ap.add_argument("-r", "--recursive", action = "store_true", help = "when looking for FILE,  traverse WinSxS recursively (takes eternity to complete)")
    ap.add_argument("-a", "--all-files", action = "store_true", help = "enumerate all files")
    ap.add_argument("-n", "--all-entries", action = "store_true", help = "enumerate all WinSxS entries")
    ap.add_argument("-p", "--path-to-winsxs", required = False, help = "a path to WinSxS (if different from the default)")

    ags = ap.parse_args()

    if not ags.path_to_winsxs:
        WinSxS.set_default_path_to_winsxs()
    else:
        WinSxS.winsxs_path = ags.path_to_winsxs

    if ags.file:
        wss = WinSxS(ags.file, ags.recursive)
        print("\n")
        for fid, lst in wss.versioned_files.items():
            print(f"{fid.dir} (arch = {fid.arch}, locale = {fid.locale})")
            print("~~~~~~~~~~~~~~")
            print(*lst, sep = "\n\n")
            print("\n")
            print(Sequence(lst, fid.file))
            print("\n\n")

    if ags.all_files:
        wss = WinSxS()
        for fid, lst in wss.versioned_files.items():
            print(f"({fid.arch}_{fid.dir}_{fid.locale}) {Sequence(lst, fid.file)}")

    if ags.all_entries:
        wss = WinSxS()
        for fid, lst in wss.versioned_dirs.items():
            print(f"{fid.dir} (arch = {fid.arch}, locale = {fid.locale})")
            print("~~~~~~~~~~~~~~")
            print(*lst, sep = "\n\n")
            print("\n\n")
