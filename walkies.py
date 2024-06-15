#!/usr/bin/env python3
"""This constructs minimal password and group files for a directory tree.

The idea is that it crawls the tree assembling ownerships, and then filters
those down to the ones that actually own files, or are groups that are a
primary group for a file's owner.

This lets a container resolve names for all owned files, and preserve
permissions, while not retaining users that are not relevant to that
container.
"""


import grp
import json
import os
import pwd
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class FObj(Enum):
    """In this model, there are only two types of file-like objects.  We
    don't the distinction between files and symlinks (or named pipes or
    device entries or....)
    """

    FILE = 1
    DIR = 2


@dataclass
class Ownership:
    """This represents an entity (user or group) that may own files and
    may have other entities as members.  It is an abstraction used in
    the creation of a minimal passwd/group pair."""

    name: str
    id: int
    pgrp: int
    descr: str
    files: list[Path]
    dirs: list[Path]
    members: set[str]


class Walker:

    def __init__(self, top: Path = Path(".")) -> None:
        self._top = top
        self._by_user: dict[int, Ownership] = {}
        self._by_group: dict[int, Ownership] = {}
        self._pgrps: set[int] = set()

    def build(self) -> None:
        """The main public method of the tree-walking class.  It
        constructs the by-user and by-group ownership maps.
        """
        for root, dirs, files in self._top.walk(
            top_down=False, follow_symlinks=False
        ):
            for name in files:
                self._add_thing(root / name, itype=FObj.FILE)
            for name in dirs:
                self._add_thing(root / name, itype=FObj.DIR)

        # Now we've got user and group entries for every owned file under
        # self._top, plus group entries for any group that is any user's
        # primary group.

        # Now restrict that to users who own files, groups that own files,
        # and groups that are a primary membership for a user in the first
        # set.
        self._filter_membership()

    def _add_thing(self, item: Path, *, itype: FObj) -> None:
        try:
            st = item.stat()
        except (FileNotFoundError, PermissionError):
            return
        uid = st.st_uid
        gid = st.st_gid
        uname = pwd.getpwuid(uid)[0]
        udesc = pwd.getpwuid(uid)[4]
        ugrp = pwd.getpwuid(uid)[3]
        gname = grp.getgrgid(gid)[0]
        self._pgrps.add(ugrp)
        if uid not in self._by_user:
            self._by_user[uid] = Ownership(
                name=uname,
                id=uid,
                pgrp=ugrp,
                descr=udesc,
                files=[],
                dirs=[],
                members=set(),
            )
        if gid not in self._by_group:
            self._by_group[gid] = Ownership(
                name=gname,
                id=gid,
                pgrp=gid,
                descr="",
                files=[],
                dirs=[],
                members=set(),
            )
        if ugrp not in self._by_group:
            grpdef = grp.getgrgid(ugrp)
            self._by_group[ugrp] = Ownership(
                name=grpdef[0],
                id=ugrp,
                pgrp=ugrp,
                descr="",
                files=[],
                dirs=[],
                members=set(),
            )
            for mem in grpdef[3]:
                self._by_group[ugrp].members.add(mem)
        if itype == FObj.FILE:
            self._by_user[uid].files.append(item)
            self._by_group[gid].files.append(item)
        else:
            self._by_user[uid].dirs.append(item)
            self._by_group[gid].dirs.append(item)

    def _filter_membership(self) -> None:
        uids = list(self._by_user.keys())
        # Purge all users who don't own files/dirs
        for uid in uids:
            rec = self._by_user[uid]
            if len(rec.files) == 0 and len(rec.dirs) == 0:
                del self._by_user[uid]
        # Now purge pgrps
        uids = list(self._by_user.keys())
        pgrps = set()
        for uid in uids:
            pwent = pwd.getpwuid(uid)
            pgrp = pwent[3]
            pgrps.add(pgrp)
        self._pgrps = pgrps

        for gid in self._by_group:
            # Filter out any group that doesn't own files/dirs and isn't
            # in any pgrps
            rec = self._by_group[gid]
            if not (
                len(rec.files) > 0 or len(rec.dirs) > 0 or gid in self._pgrps
            ):
                del self._by_group[gid]

        # Now filter membership to users that are still left.
        for gid in list(self._by_group.keys()):
            rec = self._by_group[gid]
            mems = rec.members
            if len(mems) == 0:
                continue
            # Only keep memberships attached to file-owning users.
            keep: set[str] = set()
            for mem in mems:
                urec = pwd.getpwnam(mem)
                if urec[2] in self._by_user:
                    keep.add(mem)
            rec.members = keep

    def report(self) -> None:
        passwd = ""
        for uid in sorted(list(self._by_user.keys())):
            rec = self._by_user[uid]
            passwd += f"{rec.name}:*:{rec.id}:{rec.pgrp}:::\n"
        group = ""
        for gid in sorted(list(self._by_group.keys())):
            rec = self._by_group[gid]
            mem_name_str = ",".join(rec.members)
            group += f"{rec.name}:*:{rec.id}:{mem_name_str}\n"
        pw = Path("./passwd")
        pw.write_text(passwd)
        gp = Path("./group")
        gp.write_text(group)

        # Helpful for debugging
        if os.environ.get("DEBUG", ""):
            print(f"passwd\n------\n{passwd}\n\n")
            print(f"group\n-----\n{group}\n\n")
            print("\nnot-root-owned\n--------------\n")
            for uid in self._by_user:
                if uid == 0:
                    continue
                rec = self._by_user[uid]
                print(
                    f"U: {rec.name}[{rec.id}]: F: "
                    f"{[str(x) for x in rec.files]} "
                    f"D:  {[str(x) for x in rec.dirs]}"
                )
            for gid in self._by_group:
                if gid == 0:
                    continue
                rec = self._by_group[gid]
                print(
                    f"G: {rec.name}[{rec.id}]: F: "
                    f"{[str(x) for x in rec.files]} "
                    f"D:  {[str(x) for x in rec.dirs]}"
                )


def main() -> None:
    # Very simple CLI: pass the directory to scan as the first argument,
    # or use the cwd.  The cwd must be writeable.
    if len(sys.argv) < 2:
        wk = Walker()
    else:
        wk = Walker(Path(sys.argv[1]))
    wk.build()
    wk.report()


if __name__ == "__main__":
    main()
