#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
from argparse import ArgumentParser
import importlib
from typing import List

from ..rpc import RPCServer, RPCConnectionError
from ..rpc.fifo import DualFifo
from ..rpc.unix_socket import ServerSocket

from .config import Config
from .component import Component

from . import constants as consts   
from .session import Session

import logging            
import logging.config

from ..utils import logutils

_module_logger=logging.getLogger(__name__)
_module_logger.addHandler(logging.StreamHandler())
_module_logger.setLevel(logging.INFO)

class FifoWrapper:
    def __init__(self, client_to_server, server_to_client):
        self._fifo = DualFifo(client_to_server,server_to_client)
        
    def accept(self):
        return self._fifo.connect_to_client()
    
    def __enter__(self):
        return self
    
    def __exit__(self,exc_type, exc_value, traceback):
        pass

class InvalidConfigError(Exception):
    pass    
class System:
    _logger:logging.Logger=None
    
    _config:Config=None
    
    _components:dict[str,Component] = dict()
    
    _init_order:List[str] = None
    
    _current_session:Session = None
    
    @staticmethod
    def set_config(conf:Config):
        System._config = conf
    
    @staticmethod
    def get_config()->Config:
        return System._config
    
    @staticmethod
    def get_session()->Session:
        return System._current_session
    
    @staticmethod
    def register_component(component_name:str, instance:Component):
        System._components[component_name] = instance
        
    @staticmethod
    def get_component(component_name:str)->Component|None:
        return System._components.get(component_name,None)
    
    @staticmethod
    def start(run_once:bool=False, reset_state:bool=False):
        logger = System._logger
        
        config      = System.get_config()
        
        logger.info("Start system")
        
        conn_type:str = config.get(consts.CONFIG_KEY_SYSTEM_CONNECTOR,consts.DEFAULT_SYSTEM_CONNECTOR)
        conn_type=conn_type.upper()
        
        logger.info("connector=%s",conn_type)
        if conn_type == consts.CONNECTOR_TYPE_FIFO:
            fifo_c2s = config.get(consts.CONFIG_KEY_SYSTEM_FIFO_C2S,consts.DEFAULT_FIFO_C2S)
            fifo_s2c = config.get(consts.CONFIG_KEY_SYSTEM_FIFO_S2C,consts.DEFAULT_FIFO_S2C)
            logger.info("fifo_c2s=%s, fifo_s2c=%s",fifo_c2s, fifo_s2c)
            endpoint = FifoWrapper(fifo_c2s, fifo_s2c)
        elif conn_type == consts.CONNECTOR_TYPE_SOCKET:
            usock_path = config.get(consts.CONFIG_KEY_SYSTEM_UNIX_SOCK, consts.DEFAULT_SYSTEM_UNIX_SOCK)
            logger.info("unix_socket=%s",usock_path)
            endpoint = ServerSocket(usock_path)
        else:
            logger.critical("Unknown connector type")
            return
        

        recv_timeout:float=config.get(consts.CONFIG_KEY_SYSTEM_RECV_TIMEOUT,consts.DEFAULT_SYSTEM_RECV_TIMEOUT)
        exports     = config.get(consts.CONFIG_KEY_SYSTEM_EXPORTS, consts.DEFAULT_SYSTEM_EXPORTS)
        
        
        logger.info("exports=%s recv_timeout=%f", exports, recv_timeout)
        
        if reset_state:
            System.build_system()
            System.reset_system()
            System.shutdown_system()
        
        with endpoint:
            try:
                while True:            
                    
                    logger.info("Waiting connection from client")
                    conn=endpoint.accept()
                    
                    try:
                        
                        logger.info("Connect to client")
                        System._current_session = Session()
                        rpc_server = RPCServer(conn, exports,recv_timeout=recv_timeout)
                        rpc_server.start_service()
                        logger.info("Finished connection from client")
                        
                    except RPCConnectionError as e:
                        logger.exception("Abnormal termination of connection with client")
                        pass
                    
                    finally:

                        conn.close(timeout_sec=recv_timeout)
                        
                        if System._current_session is not None:
                            System._current_session.close()
                                            
                        System.shutdown_system()
                    
                    if run_once:
                        break
            finally:
                logger.info("System shutdown")
    
    @staticmethod
    def _create_instance(cls_str:str):
        modname,clsname = cls_str.rsplit(".",1)
        _Class = getattr(importlib.import_module(modname),clsname)
        
        instance = _Class()
        return instance
    
    @staticmethod
    def build_system():
        logger=System._logger
        logger.info("Start build_system")
        config = System.get_config()
        
        System._init_order = None
        
        components = config.get(consts.CONFIG_KEY_SYSTEM_COMPONENTS,consts.DEFAULT_SYSTEM_COMPONENTS)
        
        for component_name, component_class in components.items():
            logger.info("Start component registration: name=%s  class=%s", component_name, component_class)
            instance = System._create_instance(component_class)
            assert isinstance(instance,Component)
            System.register_component(component_name,instance)
            logger.info("Finished component registration")
        
        depends=dict()
        for component_name, _ in components.items():
            default_depends = System._components[component_name].depends()
            depends_key = f"{component_name}.{consts.CONFIG_SUBKEY_COMPONENT_DEPENDS}"
            component_depends = config.get(depends_key, default_depends)
            depends[component_name] = component_depends
        
        ordered_components = System._resolve_dependency(depends)
        System._init_order=ordered_components
        
        for cname in ordered_components:
            component = System._components[cname]
            logger.info("Start initialize component: name=%s",cname)
            component.initialize(config)
            logger.info("Finished initialize component")
        
        logger.info("Finished build_system")
    
    @staticmethod
    def _resolve_dependency(depends:dict[str,List[str]]):
        logger=System._logger
        logger.info("Start resolving dependencies between components[ %s ]", list(depends.keys()))
        
        resolved=list()
        
        remain=set(depends.keys())
        while True:
            updated=False
            
            for comp in remain:
                for d in depends[comp]:
                    if d not in resolved:
                        break
                else:
                    resolved.append(comp)
                    updated=True
            
            remain=set(depends.keys()) - set(resolved)
            
            if len(remain) == 0:
                logger.info("End of dependency resolution between components:[ %s ]", resolved)
                return resolved
            
            elif updated==False:
                logger.critical("Component Dependency Resolution Failure Unresolved Component[ %s ]", remain)
                raise InvalidConfigError(f"Component Dependency Resolution Failure Unresolved Component[ {remain} ]")
                
                    
                    
           
            
    @staticmethod
    def shutdown_system():
        logger=System._logger
        logger.info("Start shutdown_system")
        
        if System._init_order is not None:
            shutdown_order = reversed(System._init_order)
            for cname in shutdown_order:
                component = System._components[cname]
                if component is not None:
                    logger.info("Start component shutdown: name=%s",cname)
                    component.shutdown()
                    logger.info("Finished component shutdown: name=%s",cname)
                else:
                    logger.warning("component %s does not exist", cname)
                    
        
        System._components.clear()
        System._init_order = None
        logger.info("Finish shutdown_system")

    @staticmethod
    def reset_system():
        logger=System._logger
        logger.info("Start reset_system")
        
        if System._init_order is not None:
            reset_order = reversed(System._init_order)
            for cname in reset_order:
                component = System._components[cname]
                if component is not None:
                    logger.info("Start component reset: name=%s",cname)
                    component.reset()
                    logger.info("Finish component reset: name=%s",cname)
                    
            
        


    @staticmethod
    def initialize():
        System._logger = logutils.get_classlogger(System)
        
    
                
    
def init_log(conf:Config):
    log_fname = conf.get(consts.CONFIG_KEY_LOG_FILENAME,consts.DEFAULT_LOG_FILENAME)
    log_level = conf.get(consts.CONFIG_KEY_LOG_LEVEL,consts.DEFAULT_LOG_LEVEL)
    log_level = log_level.upper()
    
    log_size  = conf.get(consts.CONFIG_KEY_LOG_MAX_MEGA_BYTES,consts.DEFAULT_LOG_MAX_MEGA_BYTES)
    log_backups=conf.get(consts.CONFIG_KEY_LOG_BACKUPS,consts.DEFAULT_LOG_BACKUPS)
    
    _module_logger.info("Log file name: %s",log_fname)
    _module_logger.info("Log level: %s",log_level)
    _module_logger.info("Maximum log file size: %d(MB)",log_size)
    _module_logger.info("Log backup generation: %d",log_backups)
    
    v = getattr(logging,log_level,None)
    if not isinstance(v, int):
        raise InvalidConfigError("Invalid log level({})".format(consts.CONFIG_KEY_LOG_LEVEL))
    
    try:
        log_size = int(log_size) * (1000000)
    except ValueError:
        raise InvalidConfigError("Invalid log file size({})".format(consts.CONFIG_KEY_LOG_MAX_MEGA_BYTES))
    
    try:
        log_backups=int(log_backups)
    except ValueError:
        raise InvalidConfigError("Invalid log backup generation({})".format(consts.CONFIG_KEY_LOG_BACKUPS))
    
    log_conf = Config()
    log_conf.load_dict(consts.LOG_CONFIG)
    
    log_conf.set(consts.LOG_CONFIG_KEY_FILENAME,log_fname)
    log_conf.set(consts.LOG_CONFIG_KEY_LOGLEVEL,log_level)
    log_conf.set(consts.LOG_CONFIG_KEY_MAXBYTES,log_size)
    log_conf.set(consts.LOG_CONFIG_KEY_BACKUPS,log_backups)
    
    logging.config.dictConfig(log_conf.get_dict())
    
    
        
        
  
        

def main():
    #
    # setup argument parser
    #
    argp = ArgumentParser()    
    argp.add_argument("-c","--config",metavar="config_file", help="Configuration file path (if omitted):%(default)s)",required=False,default=consts.DEFAULT_CONFIG_FILE)
    argp.add_argument("--once", action="store_true", help="Exit after client disconnect")
    argp.add_argument("--clean",action="store_true", help="Clear database and start")
    args = argp.parse_args()

    # load config
    conf:Config = Config()
    conf.load(args.config)
        
    init_log(conf)
    
    System.set_config(conf)
    # initialize System (Not initializing components!)
    System.initialize()
    
    # system start
    System.start(run_once=args.once, reset_state=args.clean)

if __name__ == "__main__":
    main()
    
    
