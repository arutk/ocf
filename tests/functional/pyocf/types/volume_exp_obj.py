from ctypes import c_int, c_void_p, CFUNCTYPE, byref

from ..ocf import OcfLib
from .volume import Volume, VOLUME_POISON
from .core import Core
from pyocf.utils import Size
from pyocf.types.data import Data
from pyocf.types.io import IoDir
from pyocf.types.shared import OcfCompletion

class ExpObjVolume(Volume):
    def __init__(self, cc, uuid = None):
        super().__init__(uuid)
        self.cc = cc
        self.volume = cc.get_volume()

    def __alloc_io(self, addr, _bytes, _dir_, _class, _flags):
        queue = self.core.cache.get_default_queue(),  # TODO multiple queues?
        exp_obj_io = cc.new_io(queue, addr, _bytes, _dir, _class, _flags)
        return exp_obj_io

    def _alloc_io(self, io):
        exp_obj_io = self.__alloc_io(io._addr, io._bytes,
                io._dir, io._class, io._flags)

        exp_obj_io.set_data(io.data)

        @CFUNCTYPE(c_void_p, c_int)
        def cb(error):
            nonlocal io
            io.callback(error)

        exp_obj_io.callback = cb

        return exp_obj_io

    def get_length(self):
        return OcfLib.getInstance().ocf_volume_get_length(self.volume)

    def get_max_io_size(self):
        return OcfLib.getInstance().ocf_volume_get_max_io_size(self.volume)

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
        pass

    def reset_stats(self):
        pass

    def _read(self, offset = 0, size = 0):
        if size == 0:
            size = self.get_length().B - offset
        exp_obj_io = self.__alloc_io(offset, size, IoDir.READ, 0, 0)
        completion = OcfCompletion([("err", c_int)])
        exp_obj_io.callback = completion
        data = Data.from_bytes(bytes(size))
        exp_obj_io.set_data(data)
        exp_obj_io.submit()
        completion.wait()
        error = completion.results["err"]
        if error:
            raise Exception("error reading exported object for dump")
        return data 

    def dump(self, offset=0, size=0, ignore=VOLUME_POISON, **kwargs):
        data = self._read(offset, size)
        data.dump(ignore = ifnore, **kwargs)

    def md5(self):
        pass




