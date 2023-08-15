#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
from .component import Component
from .config import Config

import pg8000.dbapi as pgapi

from contextlib import contextmanager

CONFIG_KEY_DBMS_DBNAME    ="DBMS.dbname"
CONFIG_KEY_DBMS_DBUSER    ="DBMS.user"
CONFIG_KEY_DBMS_DBPASSWORD="DBMS.password"
CONFIG_KEY_DBMS_HOST      ="DBMS.host"
CONFIG_KEY_DBMS_PORT      ="DBMS.port"

DEFAULT_DBMS_DBNAME = "catsdb"
DEFAULT_DBMS_DBUSER = "postgres"
DEFAULT_DBMS_DBPASSWORD="password"
DEFAULT_DBMS_HOST =None
DEFAULT_DBMS_PORT =None

class DBMSError(RuntimeError):
    pass

class DBMS(Component):
            
    def __init__(self):
        self._conn:pgapi.Connection = None
    
    def initialize(self, config: Config) -> None:
        logger=self.logger()
        
        dbname=config.get(CONFIG_KEY_DBMS_DBNAME, DEFAULT_DBMS_DBNAME)
        dbuser=config.get(CONFIG_KEY_DBMS_DBUSER, DEFAULT_DBMS_DBUSER)
        dbpass=config.get(CONFIG_KEY_DBMS_DBPASSWORD, DEFAULT_DBMS_DBPASSWORD)
        
        dbhost=config.get(CONFIG_KEY_DBMS_HOST, DEFAULT_DBMS_HOST)
        dbport=config.get(CONFIG_KEY_DBMS_PORT, DEFAULT_DBMS_PORT)
        
        args = {
            "database":dbname,
            "user":dbuser,
            "password":dbpass,
        }
        if dbhost is not None:
            args["host"] = dbhost
        if dbport is not None:
            args["port"] = int(dbport)
            
        try:
            self._conn = pgapi.connect(**args)
        except pgapi.Error as e:
            logger.exception("Fail to connect DB")
            raise DBMSError(f"Fail to connect DB({dbname})") from e
    
    def shutdown(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
                self._conn = None
            except pgapi.Error as e:
                raise DBMSError("Fail to close DB") from e
                
    
    def cursor(self):
        class wrapper:
            def __init__(self,cur:pgapi.Cursor):
                self._cur=cur
            def __enter__(self):
                return self
            def __exit__(self, exc_type, exc_value, traceback):
                self._cur.close()
            def __getattr__(self,name):
                return getattr(self._cur,name)
            
        try:
            cur = self._conn.cursor()
            return wrapper(cur)
        except pgapi.Error as e:
            raise DBMSError("Fail to get cursor") from e
           
    
    def dict_cursor(self):
        class dict_cur:
            def __init__(self, cur:pgapi.Cursor):
                self._cur = cur
                
            def _row_to_dict(self,row):
                descs = self._cur.description
                if row is not None:
                    return dict( [(desc[0],cell) for desc,cell in zip(descs,row)] )
                else:
                    return None
                
            def fetchone(self):
                return self._row_to_dict(self._cur.fetchone())
            
            def fetchmany(self, *args):
                return [ self._row_to_dict(row) for row in self._cur.fetchmany(*args) ]
            
            def fetchall(self):
                return [ self._row_to_dict(row) for row in self._cur.fetchall() ]
            
            def __getattr__(self,name):
                return getattr(self._cur,name)
            
            def __enter__(self):
                return self
            
            def __exit__(self, exc_type, exc_value, traceback):
                self._cur.close()
                
                
        try:
            cur = dict_cur(self._conn.cursor())
            return cur
        except pgapi.Error as e:
            raise DBMSError("Fail to get dict_cursor") from e
            
    def commit(self):
        try:
            self._conn.commit()
        except pgapi.Error as e:
            raise DBMSError("Fail to commit DB") from e

