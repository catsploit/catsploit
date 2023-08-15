#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#

from collections.abc import Callable
from typing import Any, Generator
from ..utils import logutils


class Runner:

    @classmethod
    def logger(cls):
        return logutils.get_logger(cls)

    def run(
        self,
        command_block: str,
        vars: dict[str, Any],
        *,
        readline_timeout_sec: float = None
    ):
        pass

    def readlines(self) -> Generator[str, None, None]:
        return iter([])

    def wait(self) -> int:
        return 0

    def close(self):
        pass


class PyRunner(Runner):

    def __init__(self, ext: dict[str, Callable] = None):
        self._ext = ext

    def run(self, command_block, vars, *, readline_timeout_sec=None):

        g = {"__builtins__": globals()["__builtins__"]}

        def set_var(key, val):
            vars[key] = val

        def get_var(key):
            return vars[key]

        def get_last_result():
            if ScriptContext._last_ctx is not None:
                last_ctx = ScriptContext._last_ctx
                return last_ctx.resultcode, last_ctx.output
            else:
                return None

        g["set_var"] = set_var
        g["get_var"] = get_var
        g["get_last_result"] = get_last_result

        if self._ext is not None:
            g.update(self._ext)

        exec(command_block, g)


class ScriptContext:

    _last_ctx = None

    @classmethod
    def logger(cls):
        return logutils.get_logger(cls)

    def __init__(self, runner: Runner):
        self._resultcode = None

        self._output = None

        self._runner = runner
        self._running = False
        self._run_args = None

        self._outbuf = list()

        self._iter_stdout_readlines = None

    def run(
        self,
        command_block: str,
        vars: dict[str, Any],
        *,
        readline_timeout_sec: float = None
    ):
        self._resultcode = None
        self._output = None
        self._outbuf.clear()

        copied_vars = dict(vars)
        self._run_args = (command_block, copied_vars)

        self._runner.run(command_block, vars, readline_timeout_sec=readline_timeout_sec)
        self._iter_stdout_readlines = self._runner.readlines()
        self._running = True

        ScriptContext._last_ctx = self

    def readlines(self) -> Generator[str | None, None, None]:
        for l in self._iter_stdout_readlines:
            if l is not None:  # None if timeout occured
                self._outbuf.append(l)
            yield l

    def is_running(self) -> bool:
        return self._running

    @property
    def output(self) -> str:
        if self._running:
            self.wait()
        return self._output

    @property
    def resultcode(self) -> int:
        if self._running:
            self.wait()
        return self._resultcode

    @property
    def runner(self) -> Runner:
        return self._runner

    @property
    def run_args(self) -> tuple[str, dict[str, Any]]:
        return self._run_args

    def wait(self):
        if self._running:
            remain = [l for l in self._iter_stdout_readlines if l is not None]
            self._outbuf.extend(remain)

            self._resultcode = self._runner.wait()
            self._output = "".join(self._outbuf)
            self._running = False

    def close(self):
        self.wait()
        self._runner.close()


class ScriptBlock:

    CONTEXT_HEADER = "|>"

    @classmethod
    def logger(cls):
        return logutils.get_logger(cls)

    def __init__(self):
        self._contexts = dict()
        self._ctx_list = list()
        self._cur_ctx = None
        self._outiter = None

    def _parse_ctx_header(self, context_header: str) -> tuple[str, str, list[str]]:
        header_body = context_header[len(ScriptBlock.CONTEXT_HEADER) :].strip()
        tokens = header_body.split(" ")

        first_token = tokens[0]
        if ":" in first_token:
            ctxtype, name = first_token.lower().split(":", 1)
        else:
            ctxtype = first_token
            name = "_context_{:d}".format(len(self._ctx_list))

        ctxtype = ctxtype.lower()

        return ctxtype, name, tokens[1:]

    def loads(self, block_str: str):
        cur_entry = None
        commands = list()
        for line in block_str.splitlines():
            if line.startswith(ScriptBlock.CONTEXT_HEADER):
                ctxtype, name, args = self._parse_ctx_header(line)
                entry = {"type": ctxtype, "name": name, "args": args, "command": None}

                self._ctx_list.append(entry)

                if cur_entry is not None:
                    cur_entry["command"] = "\n".join(commands)
                cur_entry = entry
                commands.clear()
            elif cur_entry is not None:
                commands.append(line)

        if cur_entry is not None:
            cur_entry["command"] = "\n".join(commands)

    def run(self, vars: dict[str, str], runner_providers: dict[str, Callable]):
        self.start(vars, runner_providers, read_timeout_sec=1.0)
        self.wait()

    def start(
        self,
        vars: dict[str, str],
        runner_providers: dict[str, Callable],
        *,
        read_timeout_sec=1.0
    ):
        self._outiter = self._run(
            vars, runner_providers, read_timeout_sec=read_timeout_sec
        )

    def wait(self):
        for _ in self.readlines():
            pass

    def _run(
        self, vars: dict[str, str], runner_providers: dict, *, read_timeout_sec=1.0
    ) -> Generator[str, None, None]:
        logger = self.logger()
        logger.info("Start script block")
        self._cur_ctx = None

        for entry in self._ctx_list:
            ctxname = entry["name"]

            if entry["type"] == "switch":
                ctxname = entry["args"][0].lower()
                ctx = self._contexts[ctxname]

            else:
                props = dict()
                for arg in entry["args"]:
                    k, v = arg.split("=", 1)
                    k = k.lower()
                    v = v.format(**vars)
                    props[k] = v

                provider = runner_providers[entry["type"]]

                runner = provider(props)

                ctx = ScriptContext(runner)
                self._contexts[ctxname] = ctx

            if ctx.is_running():
                ctx.wait()
                if ctx.resultcode != 0:
                    logger.error(
                        "Error in executing context %s: command=%s :out=%s",
                        entry["name"],
                        ctx._run_args,
                        ctx.output,
                    )
                    raise RuntimeError(
                        "Error in executing context {}: command={} :out={}".format(
                            entry["name"], ctx._run_args, ctx.output
                        )
                    )

            ctx.run(entry["command"], vars, readline_timeout_sec=read_timeout_sec)
            self._cur_ctx = ctx

            for l in ctx.readlines():
                if l is None:
                    break
                yield l

        last_ctx = self._cur_ctx
        if last_ctx is not None:
            # wait until last context finishes.
            for l in last_ctx.readlines():
                yield l

            if last_ctx.resultcode != 0:
                logger.error(
                    "Error in executing context %s: command=%s :out=%s",
                    entry["name"],
                    ctx.run_args,
                    ctx.output,
                )
                raise RuntimeError(
                    "Error in executing context {}}: command={} :out={}".format(
                        entry["name"], ctx.run_args, ctx.output
                    )
                )

        logger.info("Finish script block")

    def readlines(self) -> Generator[str, None, None]:
        return self._outiter


class AttackStep:

    @staticmethod
    def _always_1(*args, **kwargs):
        return 1

    def __init__(
        self,
        name: str,
        pddl_action_def: str,
        script: str,
        success_rate: Callable = None,
        evd_factors: dict[str, Any] = None,
    ):
        self._name: str = name
        self._pddl_action_def: str = pddl_action_def
        self._script: str = script

        if success_rate is not None:
            self._calc_success_rate: Callable = success_rate
        else:
            self._calc_success_rate = AttackStep._always_1

        if evd_factors is not None:
            self._evd_factors = evd_factors
        else:
            self._evd_factors = dict()

        self._sblock = None

    @property
    def name(self):
        return self._name

    @property
    def pddl_action(self):
        return self._pddl_action_def

    @property
    def script(self):
        return self._script

    @property
    def calc_success_rate(self):
        return self._calc_success_rate

    @property
    def evd_factors(self) -> dict[str, Any]:
        return self._evd_factors

    def execute(self, vars: dict[str, str], runner_providers: dict[str, Callable]):
        sb = ScriptBlock()
        sb.loads(self._script)

        providers = {"python": lambda props: PyRunner()}
        providers |= runner_providers

        sb.run(vars, providers)

    def start(self, vars: dict[str, str], runner_providers, *, read_timeout=1.0):

        sb = ScriptBlock()
        sb.loads(self._script)

        providers = {"python": lambda props: PyRunner()}

        providers |= runner_providers
        sb.start(vars, runner_providers, read_timeout_sec=read_timeout)
        self._sblock = sb

    def readlines(self, ignore_timeout=True) -> Generator[str | None, None, None]:
        for l in self._sblock.readlines():
            if l is None and ignore_timeout == True:
                continue
            yield l

    def wait(self):
        for _ in self.readlines():
            pass
