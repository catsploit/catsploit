#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
from typing import Any
from ruamel.yaml import YAML
from copy import deepcopy
import logging

class Config:
    def __init__(self):
        self._conf=dict()
       
    def load(self, config_file):
        """

        Parameters
        ----------
        config_file : str or path-like
            File written in UTF-8 YAML
        """
        with open(config_file,"r") as fp:
            conf = fp.read()
            self.loads(conf)
    
    def loads(self, config_str):
        """
        Parameters
        ----------
        config_str : str
            string (YAML)
        """
        yaml=YAML(typ='safe')
        conf = yaml.load(config_str)
        self._conf=conf
        
    def load_dict(self, d:dict):
        """convert to dict
        
        Parameters
        ----------
        d : dict
        """
        self._conf = deepcopy(d)
    
    def get_dict(self)->dict:
        """convert Config to dict
        """
        return deepcopy(self._conf)
        
    
    def get(self,key:str,default=None)->Any:
        """

        Parameters
        ----------
        key : str
            key
        """
        logging.info("key:%s"%key)
        cur = self._conf
        for k in key.split("."):
            if isinstance(cur,dict) == True:
                if k not in cur:
                    return default
                cur = cur[k]
            else:
                return default

        return cur

    def set(self, key:str, value):
        """
        Parameters
        ----------
        key : str
            setting key name
        value : Any
            setting value
        """
        cur = self._conf
        paths = key.split(".")
        dirs,last_key = paths[:-1], paths[-1]
        
        for k in dirs:
            if k not in cur:
                next_cur = dict()
                cur[k] = next_cur
            else:
                next_cur = cur[k]
                if isinstance(next_cur,dict) == False:
                    raise TypeError(f"Key{k} is already set")

                    
            cur = next_cur
        
        cur[last_key] = value
        
        
