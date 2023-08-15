#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
import random, string

def random_id_generator() -> str:
    """ID generation
        Return 6 alphanumeric random characters

        Parameters
        --------
        None

        Returns
        --------
        id: str
            6 alphanumeric characters
        
    """
    id = ''.join(random.choices(string.ascii_letters + string.digits,k=6)).lower()

    return id