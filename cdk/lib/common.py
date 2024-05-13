import re


class Common():
    def __init__(self, env_name=None, app_name=None):
        if not env_name or not app_name:
            return

        self.env_name = env_name
        self.app_name = app_name

    def id_str(self, txt: str, delim='-'):
        return delim.join((self.env_name, self.app_name, txt))

    @staticmethod
    def chunks(lst: list, n) -> dict:
        """
        chunks()
        This function accepts a list of strings and returns a hashed map list
        using a modulus as the key to the mapped list.

        We convert every character of the repo name string into its numeric value
        using ord, sum up the results and then modulus it with n. This creates a
        good random distribution to fill out our n stacks. For example, using our
        existing (2022/06/22) count of 73 repos, and an n value of 5 stacks, we
        see this distribution:

        stack: 0 -- count 13
        stack: 1 -- count 16
        stack: 2 -- count 16
        stack: 3 -- count 11
        stack: 4 -- count 17
        """
        hashed_list = dict()
        for i in lst:
            snum = 0
            for c in i:
                snum += ord(c)
            m = snum % n
            if hashed_list.get(m):
                hashed_list[m].append(i)
            else:
                hashed_list[m] = list()
                hashed_list[m].append(i)
        return hashed_list
