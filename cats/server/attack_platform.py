#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
import re
from pathlib import PureWindowsPath
import base64
import binascii
import subprocess
from typing import Any
from collections.abc import Iterable
import time
from datetime import datetime

from ..utils import launch_helper


# metasploit
from pymetasploit3.msfrpc import (
    MsfRpcClient,
    ModuleManager,
    MsfSession,
    MeterpreterSession,
    ShellSession,
    MsfModule,
    MsfConsole,
    PayloadModule,
)

from .component import Component
from .config import Config
from . import constants as consts

from ..utils import logutils

from ..core import nmap_nw_extract

from .shell import Shell, LocalShell, SessionShell
from .runner import MsfRunner, ShellRunner


CONFIG_KEY_ATTACKPF = consts.COMPONENT_ATTACKPF
CONFIG_KEY_MSF_PASSWORD = f"{CONFIG_KEY_ATTACKPF}.msfpassword"
DEFAULT_MSF_PASSWORD = "password"

CONFIG_KEY_OPENVAS = f"{CONFIG_KEY_ATTACKPF}.openvas"

CONFIG_KEY_OPENVAS_HELPER=f"{CONFIG_KEY_OPENVAS}.helper"

CONFIG_KEY_OPENVAS_SOCKET = f"{CONFIG_KEY_OPENVAS}.socket"

CONFIG_KEY_OPENVAS_USER = f"{CONFIG_KEY_OPENVAS}.user"

CONFIG_KEY_OPENVAS_PASSWORD = f"{CONFIG_KEY_OPENVAS}.password"

CONFIG_KEY_OPENVAS_MAXCHECKS = f"{CONFIG_KEY_OPENVAS}.maxchecks"

CONFIG_KEY_OPENVAS_MAXHOSTS = f"{CONFIG_KEY_OPENVAS}.maxhosts"

DEFAULT_OPENVAS_HELPER=["python3","./cats-helpers/openvas_helper.py"]

DEFAULT_OPENVAS_SOCKET = "/run/gvmd/gvmd.sock"

DEFAULT_OPENVAS_MAXCHECKS = "4"

DEFAULT_OPENVAS_MAXHOSTS = "20"

DEFAULT_OPENVAS_USER = "admin"

DEFAULT_OPENVAS_PASSWORD = "admin"

NMAP_XML_OUTPUT = "/tmp/cats-server-nmap-result.xml"




class CatsModuleManager:
    @classmethod
    def logger(cls):
        return logutils.get_logger(cls)

    def __init__(self, manager: ModuleManager):
        self._cats_manager = manager

    def __getattr__(self, name):
        return getattr(self._cats_manager, name)

    def search(self, keyword: str = None, **kwargs: dict[str, str]) -> list[MsfModule]:
        """
        Parameters
        ----------
        keyword : str, optional
            search keyword

        kwargs : dict[str, str], optional
            search condition

        Returns
        -------
        list of MsfModule
        """
        logger = self.logger()

        if keyword is None:
            keyword = ""

        query_units = [keyword] + [f"{k}:{v}" for k, v in kwargs.items()]

        qstring = " ".join(query_units)
        founds = self._cats_manager.rpc.call("module.search", [qstring])

        mods = list()
        for m in founds:
            mtype, mname = m["fullname"].split("/", 1)
            mval = {"mtype": mtype, "mname": mname}
            mods.append(mval)

        #        rval = [ self._cats_manager.use(**m) for m in mods ]
        rval = list()
        for m in mods:
            try:
                mod = self._cats_manager.use(**m)
            except:
                logger.warning("search: Failed to load module %s ... Ignored", mval)
            rval.append(mod)

        return rval


class CatsMsfRpcClient(MsfRpcClient):
    """Wrapper of MsfRpcClient
    """

    def __init__(self, *args):
        """Constructor
        """
        super().__init__(*args)

    @property
    def modules(self):
        """Return CatsModuleManager"""
        manager = super().modules
        return CatsModuleManager(manager)

    def vcall(self, method, *opts):
        """MsfRpcClient.call


        Parameters
        ----------
        method : str
            Name of method

        *opts : list

        Returns
        -------
        Any
            return method
        """
        if len(opts) == 0:
            opts = None
        else:
            opts = list(opts)

        return super().call(method, opts)


class AttackPlatform(Component):

    OSTYPE_WINDOWS = "windows"

    OSTYPE_LINUX = "linux"

    OSTYPE_UNIX = "unix"

    IP_SELF = "0.0.0.0"

    def __init__(self) -> None:
        self._msfrpcd_pid = None

    def initialize(self, config: Config) -> None:
        """
        Parameters
        ----------
        config : Config
            Config object

        Raises
        ------
        RuntimeError
            fail to connect MsfRPCd
        """
        logger = self.logger()
        password = config.get(CONFIG_KEY_MSF_PASSWORD, DEFAULT_MSF_PASSWORD)

        if self._get_pid_of_msfrpc() == 0:
            logger.info("Start MsfRPCd")
            subprocess.run(["msfrpcd", "-P", password, "-S"])
            self._msfrpcd_pid = self._get_pid_of_msfrpc()

            for i in range(10):
                try:
                    time.sleep(1)
                    self._msf_client = CatsMsfRpcClient(password)
                    break
                except Exception:
                    logger.warning("Fail to connect MsfRpcd(%d times)", i)
                    continue
            else:
                logger.error("Reach to maximum number of try to connect to MsfRpcd")
                raise RuntimeError("Fail to connect MsfRpcd")
            logger.info("Success to connect MsfRPCd")
        else:
            logger.info("Already started MsfRPCd")
            self._msf_client = CatsMsfRpcClient(password)
            logger.info("Success to connect MsfRPCd")

        self._ovas_maxchecks = config.get(
            CONFIG_KEY_OPENVAS_MAXCHECKS, DEFAULT_OPENVAS_MAXCHECKS
        )
        self._ovas_maxhosts = config.get(
            CONFIG_KEY_OPENVAS_MAXHOSTS, DEFAULT_OPENVAS_MAXHOSTS
        )

        self._ovas_helper=config.get(CONFIG_KEY_OPENVAS_HELPER, DEFAULT_OPENVAS_HELPER)
        self._ovas_sock = config.get(CONFIG_KEY_OPENVAS_SOCKET, DEFAULT_OPENVAS_SOCKET)
        self._ovas_uname = config.get(CONFIG_KEY_OPENVAS_USER, DEFAULT_OPENVAS_USER)
        self._ovas_pass = config.get(
            CONFIG_KEY_OPENVAS_PASSWORD, DEFAULT_OPENVAS_PASSWORD
        )

    def shutdown(self) -> None:
        logger = self.logger()
        logger.info("Start Shutdown")

        logger.info("Finishde Shutdown")
        
    def reset(self):
        cl = self.msf
        active_session_ids = cl.sessions.list
        for sid in active_session_ids.keys():
            cl.sessions.session(sid).stop()
        
        

    def _msf_runner_provider(self, props: dict[str, Any]):
        console = self.create_msf_console()
        return MsfRunner(console)

    def _shell_runner_provider(self, props: dict[str, str]):
        if "ip" not in props:
            shell = self.get_shell()
        else:
            ip = props["ip"]
            other_props = {k: props[k] for k in props.keys() if k != "ip"}
            sessions = self.find_sessions(ip, **other_props)
            if len(sessions) == 0:
                raise RuntimeError(
                    "Fail to Context generation: no matching session found, condition:{}".format(props)
                )

            sess = sessions[0]
            shell = self.get_shell(sess)

        return ShellRunner(shell)

    @property
    def runner_providers(self):
        return {"shell": self._shell_runner_provider, "msf": self._msf_runner_provider}

    def find_files(
        self, session: MsfSession | None, keywords: Iterable[Iterable[str]], root="/"
    ):
        logger = self.logger()

        ostype = self.get_os_type(session)

        if ostype == AttackPlatform.OSTYPE_WINDOWS:
            greps = list()
            for or_keywords in keywords:
                grep_args = " ".join(['/C:"{}"'.format(kwd) for kwd in or_keywords])
                grep_cmd = "findstr /I {}".format(grep_args)
                greps.append(grep_cmd)

            cmd_grep_pipeline = "|".join(greps)
            root_path = PureWindowsPath(root)
            cmd_line = 'dir /B /S /A "{root}" | {greps}'.format(
                root=str(root_path), greps=cmd_grep_pipeline
            )
        elif (
            ostype == AttackPlatform.OSTYPE_LINUX
            or ostype == AttackPlatform.OSTYPE_UNIX
        ):
            greps = list()
            for or_keywords in keywords:
                grep_args = " ".join(['-e "{}"'.format(kwd) for kwd in or_keywords])
                grep_cmd = "grep -iF {}".format(grep_args)
                greps.append(grep_cmd)

            cmd_grep_pipeline = "|".join(greps)
            cmd_line = 'find "{root}" -type f 2>/dev/null | {greps}'.format(
                root=root, greps=cmd_grep_pipeline
            )
        else:
            logger.warning("find_files: unknown ostype:%s", ostype)
            return []

        shell = self.get_shell(session)

        try:
            files = shell.exec(cmd_line)
            if shell.returncode != 0:
                logger.warning("An error occured in find_files:rc=%d", shell.returncode)

            return files.splitlines()
        except TimeoutError:
            logger.exception("Timelimit has expired during find_files")
            return []

    def _build_system_info_linux(
        self, vals: dict[str, str]
    ) -> dict[str, str | list[str]]:
        rval = {
            "hostname": "",
            "interfaces": [],
            "open_ports": [],
            "os_name": "",
            "arch": "",
            "users": [],
        }

        #
        # hostname
        #
        out = vals["hostname"]
        rval["hostname"] = out.strip()

        #
        # interfaces
        #

        # (ifconfig output example)
        # eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        #         inet 192.168.10.100  netmask 255.255.255.0  broadcast 192.168.10.255
        #         inet6 fe80::20c:29ff:fefa:2dbf  prefixlen 64  scopeid 0x20<link>
        #         ether 00:0c:29:fa:2d:bf  txqueuelen 1000
        #         RX packets 2788021  bytes 218754944 (208.6 MiB)
        #         RX errors 0  dropped 0  overruns 0  frame 0
        #         TX packets 4620074  bytes 407891653 (388.9 MiB)
        #         TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
        #
        # eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        #  ...

        out = vals["interfaces"]

        # output
        ifblocks = out.split("\n\n")
        rexrules = {
            "ifname": (re.compile(r"^([^:\s]+)(:|\s)"), 1),
            "ipv4": (re.compile(r"(inet |inet addr:)([\d.]+)"), 2),
            "ipv4mask": (re.compile(r"(netmask |Mask:)([\d.]+)"), 2),
            "ipv6": (re.compile(r"(inet6 (?!addr:)|inet6 addr: )([0-9a-f:]+)"), 2),
            "ipv6prefix": (re.compile(r"(prefixlen |inet6 addr: [0-9a-f:]+/)(\d+)"), 2),
        }

        ifinfo_values = list()
        for ifblock in ifblocks:
            ifblock = ifblock.strip()

            if ifblock == "":
                continue

            ifinfo = dict()
            for attr, rule in rexrules.items():
                rex = rule[0]
                grp = rule[1]
                m = rex.search(ifblock)
                if m is not None:
                    value = m[grp]
                else:
                    value = ""
                ifinfo[attr] = value

            ifinfo_tuple = tuple(
                [
                    ifinfo[attr]
                    for attr in ("ifname", "ipv4", "ipv4mask", "ipv6", "ipv6prefix")
                ]
            )
            ifinfo_values.append(ifinfo_tuple)

        rval["interfaces"] = ifinfo_values

        #
        # open ports
        #
        out = vals["open_ports"]

        # ... open ports example
        # tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
        # tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN
        # tcp        0      0 127.0.0.1:55178         127.0.0.1:9002          ESTABLISHED
        # tcp6       0      0 ::1:5432                :::*                    LISTEN
        # tcp6       0      0 :::22                   :::*                    LISTEN
        # udp6       0      0 :::9898                 :::*
        # udp        0      0 0.0.0.0:9898            0.0.0.0:*
        # udp6       0      0 ::1:34313               ::1:34313               ESTABLISHED

        rex_split = re.compile(r"\s+")
        port_values = list()
        connections = list()
        for l in out.splitlines():
            parts = rex_split.split(l)
            proto = parts[0]

            local = parts[3]
            local_addr, local_port = local.rsplit(":", 1)

            remote = parts[4]
            remote_addr, remote_port = remote.rsplit(":", 1)

            if remote_port == "*":
                port_values.append((proto, local_addr, local_port))
            else:
                # connection is/was established to some remote host.
                connections.append(
                    (proto, local_addr, local_port, remote_addr, remote_port)
                )

        rval["open_ports"] = port_values
        rval["connections"] = connections

        #
        # os_name
        #
        out = vals["os_name"]
        rval["os_name"] = out.strip()

        #
        # arch
        #
        out = vals["arch"]
        rval["arch"] = out.strip()

        #
        # users
        #
        out = vals["users"]

        uinfo_values = list()
        for l in out.splitlines():
            uname, groups_str = l.split("\t", 1)
            groups = [g.strip() for g in groups_str.split(" ")]
            uinfo_values.append((uname.strip(), groups))
        rval["users"] = uinfo_values

        return rval

    def _build_system_info_win(self, vals, shell: Shell):
        rval = {
            "hostname": "",
            "interfaces": [],
            "open_ports": [],
            "connections": [],
            "os_name": "",
            "arch": "",
            "users": [],
        }

        # systeminfo
        systeminfo_str = vals["systeminfo"]
        rex_sysinfo_attr = re.compile(r"^([^:]+):\s*(\S.*)$")

        sysinfo = dict()
        for l in systeminfo_str.splitlines():
            m = rex_sysinfo_attr.match(l)
            if m is not None:
                attr = m[1]
                val = m[2]
                sysinfo[attr] = val

        #
        # hostname
        #
        if "Host Name" in sysinfo:
            rval["hostname"] = sysinfo["Host Name"].strip()

        #
        # interfaces
        #
        ifinfos = dict()

        out = vals["interface"]

        rules = {
            "ipv4": (re.compile(r"IPv4 Address[^:]+:\s*([\d.]+)"), 1),
            "ipv4mask": (re.compile(r"Subnet Mask[^:]+:\s*([\d.]+)"), 1),
            "ipv6": (re.compile(r"IPv6 Address[^:]+:\s*([0-9a-f:%]+)"), 1),
        }

        rex_ifname = re.compile(r"^Ethernet adapter ([^:]+):")
        cur_ifname = None
        if_lines = dict()
        for l in out.splitlines():
            if l == "":
                continue

            m = rex_ifname.match(l)
            if m is not None:
                cur_ifname = m[1]
                if_lines[cur_ifname] = list()
            elif cur_ifname is not None:
                if_lines[cur_ifname].append(l)

        if_values = dict()
        for ifname, lines in if_lines.items():
            if_values[ifname] = "\n".join(lines)

        if_rval = list()
        for ifname, ifstr in if_values.items():
            ifinfo = dict()
            for attr, (rex, grp) in rules.items():
                m = rex.search(ifstr)
                if m is not None:
                    ifinfo[attr] = m[grp]
                else:
                    ifinfo[attr] = ""

            if_rval.append(
                (ifname, ifinfo["ipv4"], ifinfo["ipv4mask"], ifinfo["ipv6"], "")
            )

        rval["interfaces"] = if_rval

        #
        # open_ports
        #

        out = vals["open_ports"]
        open_ports_rval = list()
        connections_rval = list()

        def norm_endpoint(endp):
            addr, port = endp.rsplit(":", 1)
            addr = addr.replace("[", "").replace("]", "")

            return (addr, port)

        for l in out.splitlines():
            l = l.strip()
            if l == "":
                continue

            parts = l.split()
            proto, local, remote = parts[0], parts[1], parts[2]
            proto = proto.lower()

            local_addr, local_port = norm_endpoint(local)
            remote_addr, remote_port = norm_endpoint(remote)

            if ":" in local_addr:
                proto += "6"

            if remote_port == "*" or remote_port == "0":
                bind_addr, bind_port = local_addr, local_port
                open_ports_rval.append((proto, bind_addr, bind_port))
            else:
                # connection is/was established to some remote host.
                connections_rval.append(
                    (proto, local_addr, local_port, remote_addr, remote_port)
                )

        rval["open_ports"] = open_ports_rval
        rval["connections"] = connections_rval

        #
        # os_name
        #
        osname = sysinfo.get("OS Name", "Windows")
        osver = sysinfo.get("OS Version", "")
        rval["os_name"] = "{} {}".format(osname, osver)

        #
        # arch
        #
        system_type = sysinfo.get("System Type", "").lower()
        if "x64" in system_type:
            system_type = "x86_64"
        elif "x86" in system_type:
            system_type = "x86"

        rval["arch"] = system_type

        #
        # users
        #
        out = vals["users"]

        users = list()
        f_started = False
        for l in out.splitlines():
            if f_started == False:
                if l.startswith("-----"):
                    f_started = True
            else:
                if l.startswith("The command"):
                    break
                else:
                    users.extend([u for u in l.split()])

        cmd_net_users = ["chcp 437"]
        sep = "echo _____{}"
        sep_rex = re.compile(r"^_____(.*)$")
        for u in users:
            cmd_net_users.append(sep.format(u))
            cmd = f"net user {u}"
            cmd_net_users.append(cmd)

        user_rval = list()

        cmdline = "\n".join(cmd_net_users)
        whole_out = shell.exec(cmdline)

        # TODO: net user is inappropriate to get group membership information, it truncates name
        # of a group when its name is longer than some fixed length.
        rexLocalGroup = re.compile(r"Local Group Memberships\s*(.*)$")
        if shell.returncode == 0:
            user_groups = dict()
            cur_user = None
            for l in whole_out.splitlines():
                m = sep_rex.match(l)
                if m is not None:
                    cur_user = m[1]
                    user_groups[cur_user] = []
                elif l.startswith("Local Group"):
                    m = rexLocalGroup.match(l)
                    if m is not None:
                        gs = [g.strip() for g in m[1].split("*")]
                        groups = [g for g in gs if g != ""]
                        user_groups[cur_user] = groups

            for u, gs in user_groups.items():
                user_rval.append((u, gs))
        else:
            for u in users:
                user_rval.append((u, []))

        rval["users"] = user_rval

        return rval

    def get_system_info(self, session: MsfSession | None):
        logger = self.logger()

        ostype = self.get_os_type(session)
        shell = self.get_shell(session)

        sepcmd = "echo _____{}"
        seprex = re.compile(r"^_____(.*)$")

        if ostype in (AttackPlatform.OSTYPE_LINUX, AttackPlatform.OSTYPE_UNIX):
            cmdline = ";".join(
                [
                    sepcmd.format("hostname"),
                    "hostname",
                    sepcmd.format("interfaces"),
                    "ifconfig",
                    sepcmd.format("open_ports"),
                    "netstat -an|grep -E '^(tcp|udp)'",
                    sepcmd.format("os_name"),
                    "/bin/sh -c '. /etc/os-release && echo $ID $VERSION_ID'",
                    sepcmd.format("arch"),
                    "uname -m",
                    sepcmd.format("users"),
                    'for u in $(cut -d : -f 1 /etc/passwd);do printf "%s\\t%s\\n" $u "$(id -nG $u)"; done',
                ]
            )
        elif ostype == AttackPlatform.OSTYPE_WINDOWS:
            cmdline = "&".join(
                [
                    "chcp 437",
                    sepcmd.format("systeminfo"),
                    "systeminfo",
                    sepcmd.format("interface"),
                    "ipconfig",
                    sepcmd.format("open_ports"),
                    'netstat -an | findstr "TCP UDP"',
                    sepcmd.format("users"),
                    "net user",
                ]
            )

        whole_output = shell.exec(cmdline)

        val_lines = dict()
        cur_category = None
        for l in whole_output.splitlines():
            m = seprex.match(l)
            if m is not None:
                cur_category = m[1]
                val_lines[cur_category] = list()
            elif cur_category is not None:
                val_lines[cur_category].append(l)

        vals = dict()
        for cat, lines in val_lines.items():
            vals[cat] = "\n".join(lines)

        if ostype in (AttackPlatform.OSTYPE_LINUX, AttackPlatform.OSTYPE_UNIX):
            rval = self._build_system_info_linux(vals)

        elif ostype == AttackPlatform.OSTYPE_WINDOWS:
            rval = self._build_system_info_win(vals, shell)

        else:
            logger.warning("get_system_info: unknown ostype:%s", ostype)
            return rval

        return rval

    def download_file(
        self, session: MsfSession, src_file_path: str, dest_file_path: str
    ):
        logger = self.logger()
        ostype = self.get_os_type(session)

        shell = self.get_shell(session)

        if ostype in (AttackPlatform.OSTYPE_LINUX, AttackPlatform.OSTYPE_UNIX):
            cmd = 'base64 "{}"'.format(src_file_path)

        elif ostype == AttackPlatform.OSTYPE_WINDOWS:
            winpath = PureWindowsPath(src_file_path)
            cmd = '''powershell -ep bypass -c "$data=[System.IO.File]::ReadAllBytes('{src_file}'); [Convert]::ToBase64String($data)"'''.format(
                src_file=str(winpath)
            )

        else:
            raise NotImplementedError("unsupported ostype:%s", ostype)

        out = shell.exec(cmd)
        if shell.returncode != 0:
            raise RuntimeError("download_file: failed to exec %s:%s", cmd, out[:256])

        try:
            with open(dest_file_path, "wb") as wfp:
                data = base64.b64decode(out)
                wfp.write(data)
        except (binascii.Error, ValueError) as e:
            raise RuntimeError("download_file: failed to decode") from e
        except OSError as e:
            raise RuntimeError(
                "download_file: failed to open/write dest_file(%s)", dest_file_path
            ) from e

    @property
    def msf(self) -> CatsMsfRpcClient:
        return self._msf_client

    def get_shell(self, session: MsfSession = None) -> Shell:
        if session is None:
            return LocalShell()
        else:
            return SessionShell(session)

    def create_msf_console(self) -> MsfConsole:
        return self.msf.consoles.console()
    
    def enum_sessions(self):
        rval = list()
        for sid, sinfo in self.msf.sessions.list.items():
            ip = sinfo["session_host"]
            user=sinfo["username"]
            type=sinfo["type"]
            rval.append( {"ip":ip, "user":user, "type":type} )
        
        return rval
            
    def get_session_info(self, session:MsfSession):
        if session is None:
            return None
        
        sinfo:dict[str,Any] = self.msf.sessions.list[str(session.sid)]
        rval = dict()
        for d,s in zip( ["ip","user","type"],["session_host","username","type"] ):
            rval[d] = sinfo[s]
        
        return rval
        
            

    def find_sessions(
        self, ip: str, *, user: str = None, type: str = None, **kwargs: dict[str, str]
    ) -> list[MsfSession]:

        if ip == AttackPlatform.IP_SELF:
            return [None]

        found = list()

        target_value = dict()
        target_value["session_host"] = ip

        if user is not None:
            target_value["username"] = user

        if type is not None:
            target_value["type"] = type

        target_value.update(kwargs)

        for sid, sinfo in self.msf.sessions.list.items():
            sess_attrs = {k: sinfo[k] for k in target_value.keys()}
            if sess_attrs == target_value:
                found.append(self.msf.sessions.session(sid))

        return found

    def upload_file(
        self, session: MsfSession | None, local_path: str, remote_path: str
    ):

        if isinstance(session, MeterpreterSession):
            out = session.run_with_output(
                "upload {} {}".format(local_path, remote_path), ["[*] uploaded", "[-]"]
            )
            if "[-]" in out:
                raise RuntimeError("upload failed")
        else:
            ostype = self.get_os_type(session)
            if ostype not in (
                AttackPlatform.OSTYPE_LINUX,
                AttackPlatform.OSTYPE_UNIX,
                AttackPlatform.OSTYPE_WINDOWS,
            ):
                raise RuntimeError("Unsupported os type:{}".format(ostype))

            if ostype == AttackPlatform.OSTYPE_WINDOWS:
                remote_path = str(PureWindowsPath(remote_path))

            shell = self.get_shell(session)

            with open(local_path, "rb") as fp:
                data = fp.read()

            if len(data) > 0:
                tmpfile = remote_path + ".b64"
                b64str = str(base64.b64encode(data), "ascii")

                line_size = 4096
                cmds = list()
                if ostype in (AttackPlatform.OSTYPE_LINUX, AttackPlatform.OSTYPE_UNIX):
                    cmd = 'cat /dev/null > "{tmp}"'.format(tmp=tmpfile)
                else:
                    cmd = 'type nul > "{tmp}"'.format(tmp=tmpfile)

                cmds.append(cmd)
                for i in range(0, len(b64str), line_size):
                    cmd = 'echo {b64} >> "{tmp}"'.format(
                        b64=b64str[i : i + line_size], tmp=tmpfile
                    )
                    cmds.append(cmd)

                if ostype in (AttackPlatform.OSTYPE_LINUX, AttackPlatform.OSTYPE_UNIX):
                    cmds.append(
                        'base64 -d "{tmp}" > "{out}" && rm "{tmp}"'.format(
                            tmp=tmpfile, out=remote_path
                        )
                    )
                else:
                    cmds.append(
                        '''powershell -ep bypass -c "$data=[Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes('{tmp}')); [System.IO.File]::WriteAllBytes('{out}', [Convert]::FromBase64String($data)); rm '{tmp}'"'''.format(
                            tmp=tmpfile, out=remote_path
                        )
                    )

                all_cmd = "\n".join(cmds)
            else:
                if ostype in (AttackPlatform.OSTYPE_LINUX, AttackPlatform.OSTYPE_UNIX):
                    all_cmd = 'cat /dev/null > "{out}"'.format(out=remote_path)
                else:
                    all_cmd = 'type nul > "{out}"'.format(out=remote_path)

            shell.exec(all_cmd)
            if shell.returncode != 0:
                raise RuntimeError("upload failed")

    def get_os_type(self, session: MsfSession | None):
        if session is None:
            return AttackPlatform.OSTYPE_LINUX

        sid = session.sid
        sinfo: dict[str, str] = self.msf.sessions.list[sid]

        platform = sinfo.get("platform", "")

        if platform == "":
            cmd = self.get_shell(session)
            out=cmd.exec("echo $?")
            if "$?" in out:
                platform = AttackPlatform.OSTYPE_WINDOWS
            else:
                out = cmd.exec("if [ -d /proc ]; then echo 1; else echo 0;fi")
                if "1" in out:
                    platform = AttackPlatform.OSTYPE_LINUX
                else:
                    platform = AttackPlatform.OSTYPE_UNIX

        return platform

    def search_module(
        self, keyword: str = None, **kwargs: dict[str, str]
    ) -> list[MsfModule]:
        return self._msf_client.modules.search(keyword, **kwargs)

    def get_module(self, *, mtype: str, mname: str) -> MsfModule:
        return self._msf_client.modules.use(mtype, mname)

    def exec_msf_module(
        self,
        msf_module: MsfModule,
        params: dict[str, str],
        payload: PayloadModule = None,
    ):
        logger = self.logger()

        mname = msf_module.modulename
        for pname, pvalue in params.items():
            if pname not in msf_module.options:
                logger.warning("parameter %s is undefined in module %s", pname, mname)
                continue
            msf_module[pname] = pvalue
            logger.debug("set param [%s]=%s", pname, pvalue)

        if len(msf_module.missing_required) > 0:
            logger.warning(
                "parameter %s is undefined in module %s",
                msf_module.missing_required,
            )

        console = self.msf.consoles.console()
        out = console.run_module_with_output(msf_module, payload)
        console.destroy()
        return out


    def _get_pid_of_msfrpc(self):
        rc = subprocess.run(["pidof", "msfrpcd"], capture_output=True, text=True)
        if rc.returncode != 0:
            return 0
        else:
            return int(rc.stdout)

    def _stop_msfrpc(self):
        logger = self.logger()

        pid = self._get_pid_of_msfrpc()
        if pid != 0:
            logger.debug("begin: send 'core.stop'@pid=%d", pid)
            try:
                self.msf.call("core.stop")
            except Exception:
                pass
            logger.debug("done: send 'core.stop'")
            # subprocess.run(['kill',str(pid)])
            # os.waitpid(pid,0)

    @property
    def ifinfo(self):
        shell = self.get_shell()
        out = shell.exec("ip address")

        rex_ifname = re.compile(r"^\d+:\s+([^:]+):.*(UP|DOWN)")
        rex_ipv4 = re.compile(r"^\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)")

        ifinfo: dict[str, dict[str, str]] = dict()
        cur_if = None
        for l in out.splitlines():
            m = rex_ifname.match(l)
            if m is not None:
                ifname, ifstate = m[1], m[2]
                ifinfo[ifname] = {"state": ifstate}
                cur_if = ifname
            else:
                m = rex_ipv4.match(l)
                if m is not None:
                    ipv4, maskbits = m[1], int(m[2])
                    ifinfo[cur_if].update({"ipv4": ipv4, "ipv4_mask": maskbits})
        return ifinfo

    def resolve_hostname(self, host_addr):
        from socket import gethostbyaddr, herror

        try:
            host_name, *_ = gethostbyaddr(host_addr)
        except herror:
            host_name = host_addr
        return host_name

    def port_scan(
        self,
        src_host_ip: str,
        scan_range: str | list,
        scan_port: str = "1-1024",
        scan_protocol: str = "TCP",
    ):
        logger = self.logger()
        logger.info(
            "Start port scan: src_host_ip=%s scan_range=%s  scan_port=%s scan_protocol=%s",
            src_host_ip,
            scan_range,
            scan_port,
            scan_protocol,
        )

        if src_host_ip != AttackPlatform.IP_SELF:
            logger.error(
                "scanning through step stones is not implemented yet.", src_host_ip
            )
            raise NotImplementedError(
                "scanning through step stones is not implemented yet."
            )

        nmap_command = ["nmap", "-n", "-O", "-sV"]

        if scan_protocol == "TCP":
            nmap_command.append("-sT")
        elif scan_protocol == "UDP":
            nmap_command.append("-sU")
        else:
            logger.error("scan_protocol error: Invalid protocol[%s]", scan_protocol)
            raise RuntimeError(
                f"scan_protocol error: invalid protocol :[{scan_protocol}]"
            )

        nmap_command.append("-p")
        nmap_command.append(scan_port)

        nmap_command.append("-oX")
        log_filename = NMAP_XML_OUTPUT

        nmap_command.append(log_filename)
        logger.info("nmap command")
        logger.info(nmap_command)

        if isinstance(scan_range, str):
            nmap_command.append(scan_range)
        else:
            assert isinstance(scan_range, list)
            nmap_command.extend(scan_range)

        yield 10, None

        logger.info("Execute nmap")
        output_str = subprocess.run(nmap_command, capture_output=True, text=True).stdout
        logger.info("nmap result")
        logger.info(output_str)
        yield 80, None

        scan_result = nmap_nw_extract(log_filename)

        logger.info("NW SCAN OUTPUT:")
        logger.info(scan_result)

        rval = list()
        for hinfo in scan_result:
            logger.info(hinfo)

            host_ipv4 = None
            host_ipv6 = None
            for host_addr, addr_type in hinfo["addresses"]:
                if addr_type == "ipv4":
                    host_ipv4 = host_addr
                elif addr_type == "ipv6":
                    host_ipv6 = host_addr

            if host_ipv4 is not None:
                host_addr = host_ipv4
            elif host_ipv6 is not None:
                host_addr = host_ipv6
            else:
                logger.error("Fail to get ip address")
                raise RuntimeError("Fail to get ip address")

            if len(hinfo["hostnames"]) > 0:
                host_name = hinfo["hostnames"][0]
            else:
                host_name = None

            osname = None
            if len(hinfo["oss"]) > 0:
                osname, accuracy = max(hinfo["oss"], key=lambda e: e[1])

            host_info = {
                "host_addr": host_addr,
                "host_name": host_name,
                "os_name": osname,
                "ports": hinfo["ports"],
            }
            rval.append(host_info)
        yield 100, rval


    def vulnerability_scan(
        self,
        src_host_ip: str,
        scan_range: str | list,
        scan_port: str = "1-1024",
        scan_protocol: str = "TCP",
    ):
        
        logger = self.logger()

        if src_host_ip != AttackPlatform.IP_SELF:
            raise NotImplementedError(
                "vulnerability scanning through step stones is not implemented yet."
            )
                    
        params = {
            "ovas_sock": self._ovas_sock,
            "ovas_uname": self._ovas_uname,
            "ovas_pass": self._ovas_pass,
            "ovas_maxhosts":self._ovas_maxhosts,
            "ovas_maxchecks":self._ovas_maxchecks,
            "scan_range": scan_range,
            "scan_port": scan_port,
            "scan_protocol": scan_protocol
        }
        
        for progres, result in launch_helper(self._ovas_helper, params, logger):
            yield progres, result

