#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
import pickle
from typing import Any
from .connection import IConnection,RPCConnectionError
from ..utils import logutils
import logging

class _Request:
    def __init__(self,func:str, args:list[Any], kwargs:dict[str,Any]):
        self.func = func
        self.args = args
        self.kwargs=kwargs


class RPCConnectionClosed(Exception):
    pass


class RPCClient:
    """
    Communication with remote RPC server to execute function and get result
    """
    
    _logger = None
    
    @classmethod
    def logger(cls)->logging.Logger:
        """Return logger
        

        Returns
        -------
        logging.Logger
        """
        if cls._logger is None:
            cls._logger = logutils.get_classlogger(cls)
        return cls._logger

    
    def __init__(self,client:IConnection):
        """Constructor

        Parameters
        ----------
        client : IConnection
             Communication interface to server
        """
        self._client:IConnection = client
    
    def get_connection(self)->IConnection:
        return self._client

    def send_req(self,func_name, *args:list[Any], **kwargs:dict[str,Any]):
        """RPC call to server

        Parameters
        ----------
        func_name : str
            calling name of function
        
        args: list[Any]
            arguments of function
        
        kwargs: dict[str,Any]
            optional arguments of function
        
        Returns
        -------
        None
        """
        self.logger().info("Start send_req args=%s kwargs=%s",str(args), str(kwargs))
        req = _Request(
            func_name,
            args,
            kwargs
        )
        try:
            blob = pickle.dumps(req)
        except Exception as e:
            self.logger().exception('Fail to deserialize of send data')
            raise RPCConnectionError('Fail to deserialize of send data') from e

        self._client.send(blob)
        self.logger().info("End send_req")
    
    def recv_resp(self):
        """

        Returns
        -------
        resp: Any

        Raises
        ------
        resp
        """
        resp_blob = self._client.recv()
        if resp_blob is None:
            raise RPCConnectionError('Connection closed from server')
        
        try:
            resp = pickle.loads(resp_blob)
        except Exception as e:
            raise RPCConnectionError('Fail to deserialize data') from e
        
        if isinstance(resp, BaseException):
            raise resp
        
        return resp
    
    def call(self,func_name, *args:list[Any], **kwargs:dict[str,Any]):
        """call RPC
        

        Parameters
        ----------
        func_name : str
        
        args: List[Any]
            
        kwargs: Dict[str,Any]

        Returns
        -------
        Any
        
        Raises
        ------
        RPCConnectionError
        Other Exception
        """
        self.send_req(func_name, *args, **kwargs)
        return self.recv_resp()


import importlib

class RPCServer:
    _logger = None
    """logger"""
    
    @classmethod
    def logger(cls)->logging.Logger:
        """
        Returns
        -------
        logging.Logger
        """
        if cls._logger is None:
            cls._logger = logutils.get_classlogger(cls)
        return cls._logger

    
    def __init__(self, server:IConnection, exports="cats", recv_timeout=None):
        """
        
        Parameters
        ----------
        server : IStream
            Interface to client

        exports : str, optional
            name space(Name of modules)。 by default "cats"

        """
        self._server = server
        self._module = importlib.import_module(exports)
        self._recv_timeout=recv_timeout

    def fetch_and_exec_request(self):
        """
        Parameters
        ----------

        Returns
        -------
        result: bool

        """
        logger=self.logger()
        logger.info("Start recieve message")
        self._server.wait_recvable()
        blob = self._server.recv(timeout_sec=self._recv_timeout)

        if blob is None:
            # stream is closed
            logger.info("Connection termination is detected.")
            return False

        try:
            req  = pickle.loads(blob)
        except Exception as e:
            logger.exception("Fail to deserialize recieve data")
            raise RPCConnectionError('Fail to deserialize recieve data') from e

        if isinstance(req, _Request) is False:
            logger.error("Illigal data which after deserialize(type={})".format(type(req)))
            raise RPCConnectionError("Illigal data which after deserialize")

        logger.info("Finished recieve message:func=%s args=%s kwargs=%s",req.func, str(req.args), str(req.kwargs))
        
        try:
            func = getattr(self._module, req.func)
            
            logger.info("Start function call")
            resp = func(*req.args, **req.kwargs)
            logger.info("Finished function call: response=%s",resp)
            
        except Exception as e:
            logger.exception("Exception in calling function %s",req.func)
            resp = e

        logger.info("Start request sending")
        try:
            resp_blob = pickle.dumps(resp)
        except Exception as e:
            logger.exception("Fail to serialize of result of calling function.")
            raise RPCConnectionError('Fail to serialize of result of calling function.') from e

        self._server.send(resp_blob)
        logger.info("Finished send request.")
        return True

    def start_service(self):
        self.logger().info("Start start_service")
        stream_is_open = True
        while stream_is_open:
            stream_is_open = self.fetch_and_exec_request()
        self.logger().info("End start_service")

