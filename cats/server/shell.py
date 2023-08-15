#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
import subprocess
from subprocess import run, Popen, PIPE, DEVNULL
from select import poll, POLLIN, POLLOUT
import random
import re
import time

# metasploit
from pymetasploit3.msfrpc import (
    MsfSession,
    MeterpreterSession,
    ShellSession,
    MsfError,
)

from .. import utils


class Shell:
    @classmethod
    def logger(cls):
        return utils.get_logger(cls)

    def __init__(self):
        self._rc = None

    @property
    def returncode(self) -> int:
        return self._rc

    def exec(self, command_line, timeout_sec=None) -> str:
        pass

    def start(self, command_line: str):
        pass

    def read(self, timeout_sec: float = None):
        pass

    def write(self, data: str, timeout_sec: float = None):
        pass

    def close_write(self):
        pass

    def wait(self):
        pass

    def readlines(self, *, keepends: bool = False, timeout_sec: float = None):
        logger = self.logger()
        last: str = ""
        elapsed = 0
        while True:
            if timeout_sec is not None:
                if timeout_sec < elapsed:
                    logger.info("Read timeout")
                    yield None
                    elapsed = 0
                    continue
                try:
                    before_read = time.time()
                    out: str = self.read(timeout_sec - elapsed)
                    elapsed = time.time() - before_read
                except TimeoutError:
                    logger.info("Read timeout")
                    yield None
                    elapsed = 0
                    continue
            else:
                out: str = self.read(None)

            if out == "":
                if last != "":
                    yield last
                break

            for l in (last + out).splitlines(keepends=True):
                if l.endswith("\n"):
                    if not keepends:
                        l = l[:-1]
                    yield l
                    last = ""
                    elapsed = 0
                else:
                    if l != "":
                        last = l




class LocalShell(Shell):

    def __init__(self):
        super().__init__()

    def exec(self, command_line, timeout_sec=None):
        try:
            rc = run(
                command_line,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
            )
            self._rc = rc.returncode
            return rc.stdout
        except subprocess.TimeoutExpired:
            raise TimeoutError("Running timeout")

    def start(self, command_line):
        self._proc = Popen(
            command_line,
            bufsize=0,
            shell=True,
            text=True,
            stdin=PIPE,
            stdout=PIPE,
            stderr=DEVNULL,
        )

    def read(self, timeout_sec=None):
        p = poll()
        p.register(self._proc.stdout, POLLIN)

        if timeout_sec is not None:
            timeout_msec = timeout_sec * 1000
        else:
            timeout_msec = None

        result = p.poll(timeout_msec)
        if len(result) == 0:
            raise TimeoutError("Read timeout")

        chars = list()
        while len(p.poll(0)) > 0:
            c = self._proc.stdout.read(1)
            if c == "":
                self._rc = self._proc.wait()
                break
            chars.append(c)

        return "".join(chars)

    def wait(self):
        while self.read() != "":
            pass

    def write(self, data, timeout_sec=None):
        p = poll()
        p.register(self._proc.stdin, POLLOUT)

        if timeout_sec is not None:
            timeout_msec = timeout_sec * 1000
        else:
            timeout_msec = None

        result = p.poll(timeout_msec)
        if len(result) == 0:
            raise TimeoutError("Write timeout")

        n_written = 0
        for c in data:
            self._proc.stdin.write(c)
            n_written += 1

            if len(p.poll(0)) == 0:
                return n_written
        self._proc.stdin.flush()
        return n_written

    def close_write(self):
        self._proc.stdin.close()

class SessionShell(Shell):

    @staticmethod
    def _marker():
        return "".join(["{:02x}".format(random.randint(0, 255)) for i in range(8)])

    def __init__(self, session):
        super().__init__()
        self._session: MsfSession = session
        self._closed = True

    def exec(self, command_line, timeout_sec=600):
        self.start(command_line)

        ret = list()
        end_time = time.time() + timeout_sec
        now = time.time()

        while now < end_time:
            remain = int(end_time - now)
            out = self.read(timeout_sec=remain)
            if out == "":
                break
            ret.append(out)
            now = time.time()
        else:
            raise TimeoutError("Running timeout")

        return "".join(ret)

    def _start_shell(self, sess: MeterpreterSession):
        sess.write("\nshell\n")
        for i in range(10):
            out = sess.read()
            if out != "":  # Process created ...
                break
            time.sleep(1)
        else:
            raise TimeoutError("Start up shell timeout")

    def _flush_io(self):
        self._session.write("\n")
        while self._session.read() != "":
            pass

    def start(self, command_line):
        # ensure termination
        self.wait()

        self._start_maker_found = False
        start_marker = SessionShell._marker()
        finish_marker = SessionShell._marker()

        cmd = (
            f"@echo off\necho {start_marker}&&("
            + command_line.rstrip()
            + f")\necho {finish_marker} $? %ERRORLEVEL%"
        )
        self._start_marker = start_marker
        self._finish_marker = finish_marker
        self._buf = ""
        self._closed = False

        if isinstance(self._session, ShellSession):
            sess: ShellSession = self._session
            self._flush_io()
            sess.write(cmd)
        else:
            sess: MeterpreterSession = self._session
            self._start_shell(sess)
            self._flush_io()
            sess.write(cmd)

    def wait(self):
        while self._closed == False:
            self.read()

    def _read(self, timeout_sec=None):

        sess: ShellSession | MeterpreterSession = self._session

        elapsed = 0

        while True:
            before_read = time.time()
            data: str = sess.read()

            parts = data.rsplit("\n", 1)
            if len(parts) > 1:
                lines, remain = parts

                rval = self._buf + lines

                self._buf = remain

                if self._start_maker_found == False:
                    it = iter(rval.splitlines())

                    for l in it:
                        if l.startswith(self._start_marker):
                            self._start_maker_found = True
                            rval = "\n".join(it)
                            break
                    else:
                        now = time.time()
                        elapsed += now - before_read
                        continue
                    if rval == "":
                        now = time.time()
                        elapsed += now - before_read
                        continue

                break
            else:
                if parts[0] != "":
                    self._buf += parts[0]

                if timeout_sec is not None:
                    now = time.time()
                    time_remain = timeout_sec - (elapsed + (now - before_read))
                    if time_remain <= 0:
                        raise TimeoutError("Read timeout")

                    time.sleep(min(1, time_remain))
                    now = time.time()
                    elapsed += now - before_read
                else:
                    time.sleep(1)

        rex = re.compile("echo {}".format(self._finish_marker) + ".* %ERRORLEVEL%\n")
        m = rex.search(rval)
        if m is not None:
            rval = rval.replace(m[0], "")

        rex = re.compile(self._finish_marker + r".*(\d+).*$")
        m = rex.search(rval)
        if m is not None:
            rcode = int(m[1])

            rval = rval.replace(m[0], "")
            self._closed = True
            self._rc = rcode
            return rval
        else:
            return rval + "\n"

    def read(self, timeout_sec=None):
        if self._closed:
            return ""

        if isinstance(self._session, ShellSession):
            return self._read(timeout_sec)

        else:
            sess: MeterpreterSession = self._session
            try:
                out = self._read(timeout_sec)
                if self._closed:
                    res = sess.detach()
                    if "result" in res:
                        if res["result"] != "success":
                            raise MsfError(
                                "Shell failed to exit on meterpreter session "
                                + sess.sid
                            )
            except TimeoutError:
                # sess.detach()
                raise

            return out

    def write(self, data, timeout_sec=None):
        self._session.write(data)
        return len(data)
