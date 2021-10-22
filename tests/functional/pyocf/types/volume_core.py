from ctypes import c_int, c_void_p, CFUNCTYPE, byref

from .volume import Volume, VOLUME_POISON
from .core import Core
from pyocf.utils import Size
from pyocf.types.data import Data
from pyocf.types.io import IoDir
from pyocf.types.shared import OcfCompletion

class CoreVolume(Volume):
    def __init__(self, core: Core, uuid = None):
        super().__init__(uuid)
        self.core = core

    def __alloc_io(self, addr, _bytes, _dir_, _class, _flags):
        queue = self.core.cache.get_default_queue(),  # TODO multiple queues?
        core_io = self.core.new_core_io(queue, addr, _bytes,
                _dir, _class, _flags)
        return core_io

    def _alloc_io(self, io):
        core_io = self.__alloc_io(io._addr, io._bytes,
                io._dir, io._class, io._flags)

        core_io.set_data(io.data)

        @CFUNCTYPE(c_void_p, c_int)
        def cb(error):
            nonlocal io
            io.callback(error)

        core_io.callback = cb

        return core_io

    def get_length(self):
        return self.core.get_stats()["size"]

    def get_max_io_size(self):
        return self.core.device.get_max_io_size()

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
        stats = self.core.get_stats()["block"]
        return {IoDir.WRITE: stats["volume_wr"]["value"],
                IoDir.READ: stats["volume_rd"]["value"]}



    def reset_stats(self):
        self.core.reset_stats()

    def dump(self, offset=0, size=0, ignore=VOLUME_POISON, **kwargs):
        if size == 0:
            size = self.get_length().B - offset
        core_io = self.__alloc_io(offset, size, IoDir.READ, 0, 0)
        completion = OcfCompletion([("err", c_int)])
        core_io.callback = completion
        data = Data.from_bytes(bytes(size))
        core_io.set_data(data)
        core_io.submit()
        completion.wait()
        error = completion.results["err"]
        if error:
            raise Exception("error reading exported object for dump")
        data.dump(ignore = ifnore, **kwargs)

    def md5(self):
        return self.core.exp_obj_md5()




