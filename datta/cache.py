from collections import OrderedDict


class Cache:
    def __init__(self, maxsize=None):
        self._cache = OrderedDict()
        self._maxsize = maxsize

    def get(self, key):
        try:
            val = self._cache.pop(key)
            self._cache[key] = val
            return val
        except KeyError:
            return None

    def set(self, key, value):
        try:
            self._cache.pop(key)
        except KeyError:
            if self._maxsize is not None and len(self._cache) > self._maxsize:
                self._cache.popitem(last=False)
        self._cache[key] = value
