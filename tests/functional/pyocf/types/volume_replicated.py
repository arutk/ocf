from threading import Lock
from .volume import Volume, VOLUME_POISON
from .io import Io
from ctypes import cast, c_void_p, CFUNCTYPE, c_int, POINTER, memmove, sizeof, pointer

import pdb

class ReplicatedVolume(Volume):
    def __init__(self, primary: Volume, secondary: Volume, uuid = None):
        super().__init__(uuid)
        self.primary = primary
        self.secondary = secondary

        if secondary.get_max_io_size() < primary.get_max_io_size():
            raise Exception("secondary volume max io size too small")
        if secondary.get_length() < primary.get_length():
            raise Exception("secondary volume size too small")

   
    def open(self):
        ret = self.primary.open()
        if ret:
            return ret
        ret = self.secondary.open()
        if ret:
            self.primary.close()
        return ret

    def close(self):
        self.primary.close()
        self.secondary.close()

    def get_length(self):
        return self.primary.get_length()

    def get_max_io_size(self):
        return self.primary.get_max_io_size()

    def _prepare_io(self, io):
        #pdb.set_trace()
        original_cb = Io.END()
        pointer(original_cb)[0] = io.contents._end
        #memmove(original_cb, io.contents._end, sizeof(io.contents._end))
        lock = Lock()
        error = 0
        io_remaining = 2

        @CFUNCTYPE(None, c_void_p, c_int)
        def cb(io, err):
            nonlocal io_remaining
            nonlocal error
            nonlocal original_cb
            nonlocal lock

            #pdb.set_trace()

            io = cast(io, POINTER(Io))

            lock.acquire()
            if err:
                error = err
            io_remaining -= 1
            finished = True if io_remaining == 0 else False
            lock.release()
            if finished:
                io.contents._end = original_cb
                original_cb(io, error)


        io.contents._end = cb
    
    def submit_io(self, io):
        self._prepare_io(io)
        #pdb.set_trace()
        self.primary.submit_io(io)
        self.secondary.submit_io(io)

    def submit_flush(self, flush):
        self._prepare_io(flush)
        self.primary.submit_flush(flush)
        self.secondary.submit_flush(flush)

    def submit_discard(self, discard):
        self._prepare_io(discard)
        self.primary.submit_discard(discard)
        self.secondary.submit_discard(discard)

    def get_stats(self):
        return self.primary.get_stats()

    def reset_stats(self):
        self.primary.reset_stats()
        self.secondary.reset_stats()

    def dump(self, offset=0, size=0, ignore=VOLUME_POISON, **kwargs):
        self.primary.dump()

    def md5(self):
        return self.primary.md5()




