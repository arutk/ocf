from ctypes import c_int, c_void_p, CFUNCTYPE, byref, c_uint32, c_uint64, cast, POINTER

from ..ocf import OcfLib
from .volume import Volume, VOLUME_POISON
from pyocf.utils import Size
from pyocf.types.data import Data
from pyocf.types.io import IoDir, Io
from pyocf.types.shared import OcfCompletion

import pdb

class ExpObjVolume(Volume):
    def __init__(self, cc, uuid = None):
        super().__init__(uuid)
        self.cc = cc
        self.volume = cc.get_volume()

    def __alloc_io(self, addr, _bytes, _dir, _class, _flags):
        queue = self.cc.get_default_queue()  # TODO multiple queues?
        exp_obj_io = self.cc.new_io(queue, addr, _bytes, _dir, _class, _flags)
        return exp_obj_io

    def _alloc_io(self, io):
        exp_obj_io = self.__alloc_io(io.contents._addr, io.contents._bytes,
                io.contents._dir, io.contents._class, io.contents._flags)

        lib = OcfLib.getInstance()
        cdata = OcfLib.getInstance().ocf_io_get_data(io)
        #data = Data.get_instance(cdata)
        #data2 = Data.shallow_copy(data)
        OcfLib.getInstance().ocf_io_set_data(byref(exp_obj_io), cdata, 0)

        def cb(error):
            nonlocal io

            #pdb.set_trace()
            io = cast(io, POINTER(Io))
            io.contents._end(io, error)
            #TODO: delete io?

        exp_obj_io.callback = cb

        return exp_obj_io

    def get_length(self):
        return Size.from_B(OcfLib.getInstance().ocf_volume_get_length(self.volume))

    def get_max_io_size(self):
        return Size.from_B(OcfLib.getInstance().ocf_volume_get_max_io_size(self.volume))

    def submit_io(self, io):
        io = self._alloc_io(io)
        io.submit()

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


lib = OcfLib.getInstance()
lib.ocf_volume_get_max_io_size.argtypes = [c_void_p]
lib.ocf_volume_get_max_io_size.restype = c_uint32
lib.ocf_volume_get_length.argtypes = [c_void_p]
lib.ocf_volume_get_length.restype = c_uint64

lib.ocf_io_get_data.argtypes = [POINTER(Io)]
lib.ocf_io_get_data.restype = c_void_p
