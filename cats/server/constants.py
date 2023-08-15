#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#

#
# config file
#
SYSTEM_ROOT = "."
MODULE_ROOT = SYSTEM_ROOT + "/cats"

# default config file path
DEFAULT_CONFIG_FILE = SYSTEM_ROOT + "/config.yaml"
"""default config file path"""

# default DB folder
DEFAULT_FOLDER_DB = MODULE_ROOT + "/db"

# Key name to component definition settings
CONFIG_KEY_SYSTEM_COMPONENTS = "system.components"
"""Key name to component definition settings"""

# Configuration key name of the module to be exported to the client
CONFIG_KEY_SYSTEM_EXPORTS = "system.rpc.exports"
"""Configuration key name of the module to be exported to the client"""

CONFIG_KEY_SYSTEM_CONNECTOR = "system.rpc.connector"
"""Communication channel type used for RPC between client and server"""

# Key name to UNIX SOCKET file path to send from client to server
CONFIG_KEY_SYSTEM_UNIX_SOCK = "system.rpc.unix_socket.path"

# Key name to file path in FIFO for sending from client to server
CONFIG_KEY_SYSTEM_FIFO_C2S = "system.rpc.fifo.client_to_server"
"""Key name to file path in FIFO for sending from client to server"""

CONFIG_KEY_SYSTEM_FIFO_S2C = "system.rpc.fifo.server_to_client"
"""Key name to file path in FIFO for sending from server to client"""

CONFIG_KEY_SYSTEM_RECV_TIMEOUT = "system.rpc.recv_timeout"
"""Receive timeout from client (float seconds)"""

CONFIG_KEY_SYSTEM_LOGGING = "system.logging"
CONFIG_KEY_LOG_FILENAME = CONFIG_KEY_SYSTEM_LOGGING + ".filename"
"""A key name specifying the log file path"""
CONFIG_KEY_LOG_LEVEL = CONFIG_KEY_SYSTEM_LOGGING + ".level"
"""Key name specifying log level"""
CONFIG_KEY_LOG_MAX_MEGA_BYTES = CONFIG_KEY_SYSTEM_LOGGING + ".max_megabytes"
"""Maximum log file size(Mbyte)"""
CONFIG_KEY_LOG_BACKUPS = CONFIG_KEY_SYSTEM_LOGGING + ".backups"
"""Number of backup generations saved"""


CONNECTOR_TYPE_FIFO = "FIFO"
"""Channel type identifier(FIFO)"""
CONNECTOR_TYPE_SOCKET = "UNIX_SOCKET"
"""Channel type identifier(UNIX SOCKET)"""

#
# Attributes common to each component
#
CONFIG_SUBKEY_COMPONENT_DEPENDS = "depends"
DEFAULT_COMPONENT_DEPENDS = []

#
# system.* related default values
#

# Default values ​​for component definition settings
DEFAULT_SYSTEM_COMPONENTS = {
    "SERVER": "cats.server.Server",
    "DBMS": "cats.server.DBMS",
    "KS": "cats.server.KnowledgeBase",
    "SCENARIO": "cats.server.ScenarioMaker",
    "ATTACKPF": "cats.server.AttackPlatform",
    "ATTACKDB": "cats.server.AttackDB"    
}

"""Default values ​​for component definition settings"""

# Default values ​​for modules exported to the client
DEFAULT_SYSTEM_EXPORTS = "cats.server.cui_exports"
"""Default values ​​for modules exported to the client"""

DEFAULT_SYSTEM_CONNECTOR = CONNECTOR_TYPE_SOCKET
"""Default communication path type between client and server"""

# FIFO file path
DEFAULT_SYSTEM_UNIX_SOCK = "/tmp/cats.usock"
"""UNIX socket file path from client to server"""

DEFAULT_FIFO_C2S = "/tmp/fifo-cats.c2s"
"""FIFO file path from client to server"""

DEFAULT_FIFO_S2C = "/tmp/fifo-cats.s2c"
"""FIFO file path from server to client"""

DEFAULT_SYSTEM_RECV_TIMEOUT = 5.0

#
# Log setting
#
DEFAULT_LOG_FILENAME = "/tmp/cats-server.log"
"""Log file path"""

DEFAULT_LOG_LEVEL = "WARNING"
"""Log level"""

DEFAULT_LOG_MAX_MEGA_BYTES = 10
"""Maximum log file size"""

DEFAULT_LOG_BACKUPS = 3
"""Saved number of backup generations"""

#
# INTERNAL
#
COMPONENT_SERVER = "SERVER"
"""Name of Server component"""
COMPONENT_DBMS = "DBMS"
COMPONENT_KS = "KS"
COMPONENT_ATTACKPF = "ATTACKPF"
COMPONENT_SCENARIO = "SCENARIO"
COMPONENT_ATTACKDB = "ATTACKDB"

LOG_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "precise": {
            "format": "[{asctime}][{process}][{thread:x}][{name}][{levelname}]: {message}",
            "style": "{",
        },
        "brief": {"format": "%(asctime)s %(message)s"},
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "brief",
            "level": "ERROR",
            "stream": "ext://sys.stderr",
        },
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "precise",
            "filename": DEFAULT_LOG_FILENAME,
            "maxBytes": DEFAULT_LOG_MAX_MEGA_BYTES,
            "backupCount": DEFAULT_LOG_BACKUPS,
        },
    },
    "root": {"level": DEFAULT_LOG_LEVEL, "handlers": ["console", "file"]},
}
"""Log setting"""

LOG_CONFIG_KEY_LOGLEVEL = "root.level"
LOG_CONFIG_KEY_FILENAME = "handlers.file.filename"
LOG_CONFIG_KEY_MAXBYTES = "handlers.file.maxBytes"
LOG_CONFIG_KEY_BACKUPS = "handlers.file.backupCount"
