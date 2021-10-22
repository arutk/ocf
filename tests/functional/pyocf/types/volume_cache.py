from ctypes import c_int, c_void_p, CFUNCTYPE, byref

from .volume import Volume, VOLUME_POISON
from .cache import Cache
from pyocf.utils import Size
from pyocf.types.data import Data
from pyocf.types.io import IoDir
from pyocf.types.shared import OcfCompletion

class CacheVolume(Volume):
    def __init__(self, cache: Core, uuid = None):
        super().__init__(uuid)
        self.cache = cache

    def __alloc_io(self, addr, _bytes, _dir_, _class, _flags):
        queue = self.cache.cache.get_default_queue(),  # TODO multiple queues?
        cache_io = self.cache.new_cache_io(queue, addr, _bytes,
                _dir, _class, _flags)
        return cache_io

    def _alloc_io(self, io):
        cache_io = self.__alloc_io(io._addr, io._bytes,
                io._dir, io._class, io._flags)

        cache_io.set_data(io.data)

        @CFUNCTYPE(c_void_p, c_int)
        def cb(error):
            nonlocal io
            io.callback(error)

        cache_io.callback = cb

        return cache_io

    def get_length(self):
        return self.cache.get_stats()["size"]

    def get_max_io_size(self):
        return self.cache.device.get_max_io_size()

    def submit_io(self, io):
        io = self._alloc_io(flush)
        io.submit_io()

    def submit_flush(self, flush):
        io = self._alloc_io(flush)
        io.submit_flush()

    def submit_discard(self, discard):
        io = self._alloc_io(discard)
        io.submit_discard()

    def get_stats(self):
        stats = self.cache.get_stats()["block"]
        return {IoDir.WRITE: stats["volume_wr"]["value"],
                IoDir.READ: stats["volume_rd"]["value"]}



    def reset_stats(self):
        self.cache.reset_stats()

    def dump(self, offset=0, size=0, ignore=VOLUME_POISON, **kwargs):
        if size == 0:
            size = self.get_length().B - offset
        cache_io = self.__alloc_io(offset, size, IoDir.READ, 0, 0)
        completion = OcfCompletion([("err", c_int)])
        cache_io.callback = completion
        data = Data.from_bytes(bytes(size))
        cache_io.set_data(data)
        cache_io.submit()
        completion.wait()
        error = completion.results["err"]
        if error:
            raise Exception("error reading exported object for dump")
        data.dump(ignore = ifnore, **kwargs)

    def md5(self):
        return self.cache.exp_obj_md5()




