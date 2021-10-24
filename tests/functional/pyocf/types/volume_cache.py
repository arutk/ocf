from .cache import Cache
from pyocf.types.io import IoDir
from .volume_exp_obj import ExpObjVolume

class CacheVolume(ExpObjVolume):
    def __init__(self, cache, uuid = None):
        super().__init__(cache, uuid)
        self.cache = cache

    def get_stats(self):
        # TODO: how?
        pass

    def reset_stats(self):
        pass

    def md5(self):
        data = self._read()
        return data.md5()


 




