#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
CSI_RED = "\033[31m"
CSI_BLUE = "\033[34m"
CSI_YELLOW = "\033[33m"
CSI_GREEN = "\033[32m"
CSI_END = "\033[0m"


def color(s: str, csi: str):
    return csi + s + CSI_END


def RED(s: str):
    return color(s, CSI_RED)


def BLUE(s: str):
    return color(s, CSI_BLUE)


def YELLOW(s: str):
    return color(s, CSI_YELLOW)


def GREEN(s: str):
    return color(s, CSI_GREEN)


def message(msg: str, prefix: str):
    for l in msg.splitlines():
        msg = f"{prefix} {l}"
        print(msg)


def warn(msg: str):
    message(msg, YELLOW("[!]"))


def error(msg: str):
    message(msg, RED("[-]"))


def success(msg: str):
    message(msg, GREEN("[+]"))


def info(msg: str):
    message(msg, BLUE("[*]"))


class Menu:
    def __init__(self, menu_list: list[str]):
        self._menu = menu_list

    def __str__(self):
        index = 0
        for value, desc in self._menu:
            print("{index}: {value}".format(index=index, value=value))
            index += 1

    def get(self, index):
        return self._menu[index]
