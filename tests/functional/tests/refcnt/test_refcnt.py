#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

import pytest
import gc

from ctypes import c_int

from pyocf.types.cache import RawCache
from pyocf.types.cache import CacheMode
from pyocf.types.cache import CleaningPolicy
from pyocf.types.core import Core
from pyocf.types.data import Data
from pyocf.types.io import IoDir
from pyocf.types.volume import Volume, ErrorDevice
from pyocf.types.queue import Queue
from pyocf.utils import Size as S
from pyocf.types.shared import OcfError, OcfCompletion
from pyocf.types.logger import LogLevel, DefaultLogger, BufferLogger
from pyocf.types.volume import Volume, ErrorDevice
from pyocf.types.ctx import get_default_ctx

def check_completion_status(cmpl, op_name):
    if cmpl.results["error"]:
        raise OcfError("{0} failed".format(op_name), cmpl.results["error"])

def prepare_io(core, queue):
    # prepare I/O
    write_data = Data.from_string("{0: <4096}".format("This is test data"))
    io = core.new_io()
    io.set_data(write_data)
    io.configure(20, write_data.size, IoDir.WRITE, 0, 0)
    io.set_queue(queue)
    return io

@pytest.fixture()
def raw_core_cache():

    ctx = get_default_ctx(DefaultLogger(LogLevel.WARN))
    ctx.register_volume_type(Volume)
    ctx.register_volume_type(ErrorDevice)

    # init volumes
    cache_device = Volume(S.from_MiB(30))
    core_device = Volume(S.from_MiB(40))

    # start cache
    cache = RawCache(owner = ctx)
    cache.start()
    cache.started = True

    # mngt queue
    mngt_queue = Queue(cache, "mngt_queue")
    cache.set_mngt_queue(mngt_queue)

    # attach device
    cache.configure_device(cache_device, force = True)
    cmpl = RawCache.create_attach_completion()
    cache.attach_device(cmpl)
    cmpl.wait()
    check_completion_status(cmpl, "Attaching cache device")

    # create IO queue
    io_queue = Queue(cache, "io_queue")

    # add core
    core = Core.using_device(core_device)

    cmpl = RawCache.create_add_core_completion()
    cache.add_core(core, cmpl)
    cmpl.wait()
    check_completion_status(cmpl, "Inserting core to cache device")
    core.cache = cache
    core.handle = cmpl.results["core"]

    # TODO: this get shouldn't be needed after OCF API is cleaned up in the
    # the context of mngt queue create/set/put usage.
    cache.get()

    fixt = {}
    fixt["ctx"] = ctx
    fixt["cache_device"] = cache_device
    fixt["core_device"] = core_device
    fixt["mngt_queue"] = mngt_queue
    fixt["cache"] = cache
    fixt["io_queue"] = io_queue
    fixt["core"] = core

    yield fixt

    if cache.started:
        cmpl = RawCache.create_stop_completion()
        cache.stop(cmpl)
        cmpl.wait()

    mngt_queue.put()
    cache.put()

    ctx.exit()
    gc.collect()

# verify proper fixture cleanup with started cache
def test_fixture_1(raw_core_cache):
    pass

# verify proper fixture cleanup with stopped cache
def test_fixture_2(raw_core_cache):
    cache = raw_core_cache["cache"]
    cmpl = RawCache.create_stop_completion()
    cache.stop(cmpl)
    cmpl.wait()
    cache.started = False

# verify that arming core device blocks I/O - this excercises test framework
# rather than OCF
def test_io_queue_arm_fire(raw_core_cache):
    cache = raw_core_cache["cache"]
    core = raw_core_cache["core"]
    io_queue = raw_core_cache["io_queue"]
    mngt_queue = raw_core_cache["mngt_queue"]
    cache_device = raw_core_cache["cache_device"]
    core_device = raw_core_cache["core_device"]
    io = prepare_io(core, io_queue)

    # make core device block I/O
    core_device.arm()

    # submit I/O
    io_cmpl = OcfCompletion([("err", c_int)])
    io.callback = io_cmpl.callback
    io.submit()

    # wait for I/O processing in OCF to finish
    io_queue.wait_idle()

    # make sure I/O is not completed
    assert not io_cmpl.finished()

    # unblock I/O
    core_device.fire()

    # wait for any remaining I/O to finish
    io_queue.wait_idle()

    # I/O should be finished now
    assert io_cmpl.finished()
    assert io_cmpl.results["err"] == 0

# verify that arming cache device blocks stop - this excercises test framework
# rather than OCF
def test_mngt_queue_arm_fire(raw_core_cache):
    cache = raw_core_cache["cache"]
    cache_device = raw_core_cache["cache_device"]
    mngt_queue = raw_core_cache["mngt_queue"]

    # block I/O on cache device
    cache_device.arm()

    # issue async stop
    cmpl = RawCache.create_stop_completion()
    cache.stop(cmpl)

    # wait for mngmt queue to idle
    mngt_queue.wait_idle()

    # stop should not be finished
    assert not cmpl.finished()

    # resume I/O on cache device
    cache_device.fire()

    # wait for mngmt queue to idle
    mngt_queue.wait_idle()

    # stop should be finished now
    assert cmpl.finished()

    cache.started = False

# verify that pending IO request blocks stop
def test_stop_io_ref_cnt_wait(raw_core_cache):
    cache = raw_core_cache["cache"]
    core = raw_core_cache["core"]
    io_queue = raw_core_cache["io_queue"]
    mngt_queue = raw_core_cache["mngt_queue"]
    cache_device = raw_core_cache["cache_device"]
    core_device = raw_core_cache["core_device"]
    io = prepare_io(core, io_queue)

    # make core device block I/O
    core_device.arm()

    # submit I/O
    io_cmpl = OcfCompletion([("err", c_int)])
    io.callback = io_cmpl.callback
    io.submit()

    # wait for I/O processing in OCF to finish
    io_queue.wait_idle()

    # make sure I/O is not completed
    assert not io_cmpl.finished()

    # attempt to stop cache
    stop_cmpl = RawCache.create_stop_completion()
    cache.stop(stop_cmpl)

    # wait for management operation processing to finish
    mngt_queue.wait_idle()

    # make sure stop is not finished
    assert not stop_cmpl.finished()

    # unblock I/O
    core_device.fire()

    # wait for any remaining I/O to finish
    io_queue.wait_idle()

    # I/O should be finished now
    assert io_cmpl.finished()
    assert io_cmpl.results["err"] == 0

    # wait for any remaining mngmt I/O to finish
    mngt_queue.wait_idle()

    # stop should be finished now
    assert stop_cmpl.finished()

    # make sure cleanup does not attempt to stop cache again
    cache.started = False

# verify that pending WT request blocks detach
def test_detach_metadata_ref_cnt_wait(raw_core_cache):
    cache = raw_core_cache["cache"]
    core = raw_core_cache["core"]
    io_queue = raw_core_cache["io_queue"]
    mngt_queue = raw_core_cache["mngt_queue"]
    cache_device = raw_core_cache["cache_device"]
    core_device = raw_core_cache["core_device"]
    io = prepare_io(core, io_queue)

    # make core device block I/O
    core_device.arm()

    # submit I/O
    io_cmpl = OcfCompletion([("err", c_int)])
    io.callback = io_cmpl.callback
    io.submit()

    # wait for I/O processing in OCF to finish
    io_queue.wait_idle()

    # make sure I/O is not completed
    assert not io_cmpl.finished()

    # attempt to detach cache device
    detach_cmpl = RawCache.create_detach_completion()
    cache.detach_device(detach_cmpl)

    # wait for management operation processing to finish
    mngt_queue.wait_idle()

    # make sure detach is not finished
    assert not detach_cmpl.finished()

    # unblock I/O
    core_device.fire()

    # wait for any remaining I/O to finish
    io_queue.wait_idle()

    # I/O should be finished now
    assert io_cmpl.finished()
    assert io_cmpl.results["err"] == 0

    # wait for any remaining mngmt I/O to finish
    mngt_queue.wait_idle()

    # detach should be finished now
    assert detach_cmpl.finished()

# submit I/O after starting detach and make sure it completes - should be
# serviced in 2dc
def test_detach_io_ref_no_wait(raw_core_cache):
    cache = raw_core_cache["cache"]
    core = raw_core_cache["core"]
    io_queue = raw_core_cache["io_queue"]
    mngt_queue = raw_core_cache["mngt_queue"]
    cache_device = raw_core_cache["cache_device"]
    core_device = raw_core_cache["core_device"]
    io = prepare_io(core, io_queue)

    # block on cache device
    cache_device.arm()

    # attempt to detach cache device - should be blocked by cache device
    detach_cmpl = RawCache.create_detach_completion()
    cache.detach_device(detach_cmpl)

    # wait for management operation processing to finish
    mngt_queue.wait_idle()

    # make sure detach is not finished
    assert not detach_cmpl.finished()

    # submit I/O
    io_cmpl = OcfCompletion([("err", c_int)])
    io.callback = io_cmpl.callback
    io.submit()

    # wait for I/O processing in OCF to finish
    io_queue.wait_idle()

    # I/O should have completed in d2c
    assert io_cmpl.finished()
    assert io_cmpl.results["err"] == 0

    # unblock I/O
    cache_device.fire()

    # wait for detach to complete
    mngt_queue.wait_idle()

    # make sure detach is finished
    assert detach_cmpl.finished()

