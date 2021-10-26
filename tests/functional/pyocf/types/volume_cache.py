from ctypes import cast, POINTER

from .cache import Cache
from .io import Io
from pyocf.types.io import IoDir
from .volume_exp_obj import ExpObjVolume

class CacheVolume(ExpObjVolume):
    def __init__(self, cache, uuid = None):
        super().__init__(cache, uuid)
        self.cache = cache

    #TODO: remove this mock after OCF properly handles
    # cache device flush I/O with no data set
    def submit_flush(self, flush):
        io = cast(flush, POINTER(Io))
        io.contents._end(io, 0)

    def get_stats(self):
        # TODO: how?
        pass

    def reset_stats(self):
        pass

    def md5(self):
        data = self._read()
        return data.md5()


 




