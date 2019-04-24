#!/usr/bin/env python3

#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

import gc

from ctypes import c_int

from pyocf.types.cache import Cache
from pyocf.types.cache import RawCache
from pyocf.types.core import Core
from pyocf.types.queue import Queue
from pyocf.types.volume import Volume, ErrorDevice
from pyocf.types.data import Data
from pyocf.types.io import IoDir
from pyocf.utils import Size as S
from pyocf.types.shared import OcfError, OcfCompletion
from pyocf.types.ctx import get_default_ctx
from pyocf.types.logger import LogLevel, DefaultLogger, BufferLogger
from tests.conftest import pyocf_ctx


# preambule
c = get_default_ctx(DefaultLogger(LogLevel.WARN))
c.register_volume_type(Volume)
c.register_volume_type(ErrorDevice)
#end of prembule

def check_completion_status(cmpl, op_name):
    if cmpl.results["error"]:
        raise OcfError("{0} failed".format(op_name), cmpl.results["error"])

cache_device = Volume(S.from_MiB(30))
core_device = Volume(S.from_MiB(30))

cache_device.arm()
cache_device.fire()

# create cache
cache = RawCache(owner = c)

# start cache
cache.start()

# set mngt queue
mngt_queue = Queue(cache, "mngt_queue")
cache.set_mngt_queue(mngt_queue)

cache.configure_device(cache_device, force = True)
attach_cmpl = RawCache.create_attach_completion()
cache.attach_device(attach_cmpl)
attach_cmpl.wait()
check_completion_status(attach_cmpl, "Attaching cache device")

# create IO queue
io_queue = Queue(cache, "io_queue")

core = Core.using_device(core_device)

add_core_cmpl = RawCache.create_add_core_completion()
cache.add_core(core, add_core_cmpl)
add_core_cmpl.wait()
check_completion_status(add_core_cmpl, "Inserting core to cache device")
core.cache = cache
core.handle = add_core_cmpl.results["core"]

write_data = Data.from_string("This is test data")
io = core.new_io()
io.set_data(write_data)
io.configure(20, write_data.size, IoDir.WRITE, 0, 0)
io.set_queue(io_queue)

cmpl = OcfCompletion([("err", c_int)])
io.callback = cmpl.callback
io.submit()
cmpl.wait()

assert cmpl.results["err"] == 0

#assert core.exp_obj_md5() == core_device.md5()


print("arming cache device")
cache_device.arm()

print("starting stop")
cmpl = RawCache.create_stop_completion()
cache.stop(cmpl)
print("stop waiting for idle")
mngt_queue.wait_idle()
if cmpl.finished():
    print("stop finished already")
else:
    print("stop not finished yet")
    print("firing device")
    cache_device.fire()
    if cmpl.finished():
        print("finished already")
    else:
        print("waiting on completion")
        cmpl.wait()
        print("stop finished after wait")

mngt_queue.put()

# teardown
c.exit()
gc.collect()
#end of teardown

