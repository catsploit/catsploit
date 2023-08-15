#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
"""
Definition of original exception classes
"""

"""
Define original exception class
"""

class IDValueError(Exception):
    """
    Exception class raised when various IDs are not found in the set of existing IDs or are of different formats
    """


class KsValueError(Exception):
    """
    This is an exception class that is thrown when the contents of K_s to be updated cannot be found in the knowledge database K_s, or when the format is different.
    """
    

class AddressValueError(Exception):
    """
    This is the exception class that is thrown when the format of the IP address is different.
    """
    

class TypeValueError(Exception):
    """
    This is an exception class that is thrown when the format of the scan type is different
    """
    

class PortValueError(Exception):
    """
    This is the exception class that is thrown when the port formats are different.
    """


class ProtocolValueError(Exception):
    """
    Exception class that is thrown when protocol format is different
    """


class StartError(Exception):
    """
    This is an exception class that is thrown when the execution of the relevant process cannot be started due to some error in the external tool.
    """


class StatusError(Exception):
    """
    This is the exception class that is thrown when you try to make a call even though it is not callable.
    """


class PathError(Exception):
    """
    Exception class that is thrown when the file path does not exist
    """

    
