#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
from .config import Config
import logging
from ..utils import logutils

class Component:
    """Abstract base class for system components
    
    Components registered with System must be subclasses of this class
    """   
    @classmethod
    def logger(cls):
        return logutils.get_logger(cls)
    
    def initialize(self,config:Config)->None:
        """Component initialization
        Parameters
        ----------
        config : Config
        """
        raise NotImplementedError()
    
    def shutdown(self)->None:
        """End of component

        """
        raise NotImplementedError()
    
    def reset(self)->None:
        """Component state reset
        
        """
        pass
    
    @classmethod
    def depends(cls)->list[str]:
        """Return component dependencies
        
        """
        return []