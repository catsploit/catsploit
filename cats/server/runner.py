#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
import time

# metasploit
from pymetasploit3.msfrpc import (
    MsfConsole,
)

from .shell import Shell
from .attack_step import Runner


class ShellRunner(Runner):

    def __init__(self, shell: Shell):
        self._shell = shell
        self._iteroutput = None
        self._is_running = False
        self._resultcode = None

    def run(self, command_block, vars, *, readline_timeout_sec=None):
        cmdlines = command_block.format(**vars)

        logger = self.logger()
        logger.info("START:%s", cmdlines)
        self._shell.start(cmdlines)
        self._iteroutput = self._shell.readlines(
            keepends=True, timeout_sec=readline_timeout_sec
        )
        self._is_running = True

    def readlines(self):
        return self._iteroutput

    def wait(self):
        logger = self.logger()
        if self._is_running:
            _ = list(self._iteroutput)
            self._resultcode = self._shell.returncode

        rc = self._resultcode
        logger.info("END: %d, %s", rc)
        return rc


class MsfRunner(Runner):

    def __init__(self, console: MsfConsole):
        self._console = console
        self._resultcode = None
        self._iter_output = None
        self._is_running = False

        # flush splash screen
        console.read()

    def run(self, command_block, vars, *, readline_timeout_sec=None):
        cmdlines = command_block.format(**vars)
        self._resultcode = None
        self._console.write(cmdlines)

        self._is_running = True
        self._iter_output = self._readlines(timeout_sec=readline_timeout_sec)

    def _readlines(self, *, timeout_sec=None):
        last = ""
        last_line = ""
        elapsed = 0

        while True:
            before_read = time.time()
            res = self._console.read()
            elapsed += time.time() - before_read

            data = res["data"]
            still_busy = res["busy"]
            if data == "" and still_busy:
                # console is blocking
                if timeout_sec is not None:
                    if timeout_sec <= elapsed:
                        yield None
                        elapsed = 0
                    else:
                        sleep_time = min(0.5, timeout_sec - elapsed)
                        time.sleep(sleep_time)
                        elapsed += sleep_time

                continue

            for l in (last + data).splitlines(keepends=True):
                if l.endswith("\n"):
                    yield l
                    last_line = l
                    elapsed = 0
                else:
                    last = l

            if still_busy == False:
                if last != "":
                    yield last
                    last_line = l
                break

        if last_line.startswith("[-]"):
            self._resultcode = -1
        else:
            self._resultcode = 0

        self._is_running = False

    def readlines(self):
        return self._iter_output

    def wait(self) -> int:
        if self._is_running:
            _ = list(self.readlines())

        return self._resultcode

    def close(self):
        self._console.destroy()