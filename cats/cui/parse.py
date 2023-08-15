#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
# args     ::= <argument>(<ws><argument>)*
# argument ::= <token> | <dqstring> | <sqstring>
# token ::= <tokenchar>+
# dqstring ::= " ( (<anychar>-["]) | <escape> )* "
# sqstring ::= ' ( (<anychar>-[']) | <escape> )* '
# escape   ::= \ <anychar>
# tokenchar ::= <anychar>-[\s"'\\]
# anychar  ::= <ascii>-\n

import re

REX_UNESCAPE = re.compile(r"\\(.)")


def _unescape(s: str):
    return REX_UNESCAPE.sub(r"\g<1>", s)


PAT_TOKEN = r"""[^\s\\"']+"""
PAT_DQSTRING = r'"(?P<DQVAL>([^\\"]|\\.)*)"'
PAT_SQSTRING = r"'(?P<SQVAL>([^\\']|\\.)*)'"
PAT_WS = r"\s+"

REX_COMMANDLINE = re.compile(
    f"(?P<TOKEN>{PAT_TOKEN})|(?P<DQSTRING>{PAT_DQSTRING})|(?P<SQSTRING>{PAT_SQSTRING})|(?P<WS>{PAT_WS})|."
)
TOKEN_SPEC = {
    "TOKEN": (0, None),
    "DQSTRING": ("DQVAL", _unescape),
    "SQSTRING": ("SQVAL", _unescape),
    "WS": (None, None),
}


def string2args(command_line: str):
    command_line = command_line.strip()
    rval = list()

    index_last_parsed = 0
    for m in re.finditer(REX_COMMANDLINE, command_line):
        token_type = m.lastgroup
        if token_type is None:
            # unexpected char is read. stop parsing and return partial result
            return rval, index_last_parsed

        grp, modifier = TOKEN_SPEC[token_type]
        if grp is not None:
            token_value = m.group(grp)
            if modifier is not None:
                token_value = modifier(token_value)

            rval.append(token_value)

        index_last_parsed = m.end()

    return rval, index_last_parsed
