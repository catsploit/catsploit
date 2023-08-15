#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
import logging

def get_classlogger(cls)->logging.Logger:
    """
    Parameters
    ----------
    cls: class
        target class object which get logger
        
    Returns
    -------
    logging.Logger
        logger object
    """
    clsname = ".".join([cls.__module__,cls.__name__])
    logger = logging.getLogger(clsname)
    return logger


    
def get_logger(cls)->logging.Logger:
    """
    Parameters
    ----------
    cls: class
        target class object which get logger
        
    Returns
    -------
    logging.Logger
        logger object
    """
    if getattr(cls,"_logger",None) is None:
        cls._logger = get_classlogger(cls)
    return cls._logger
