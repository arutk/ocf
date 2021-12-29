import pytest
from ctypes import c_int

from pyocf.types.cache import (
    Cache,
    CacheMode,
    MetadataLayout,
    CleaningPolicy,
)
from pyocf.types.core import Core
from pyocf.types.data import Data
from pyocf.types.io import Io, IoDir
from pyocf.types.volume import RamVolume
from pyocf.types.volume_cache import CacheVolume
from pyocf.types.volume_replicated import ReplicatedVolume
from pyocf.types.shared import (
    OcfError,
    OcfErrorCode,
    OcfCompletion,
    CacheLines,
    CacheLineSize,
    SeqCutOffPolicy,
)
from pyocf.utils import Size
from pyocf.rio import Rio, ReadWrite

def test_standby_stop_closes_volume(pyocf_2_ctx):
    ctx = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB
    vol = RamVolume(Size.from_MiB(150))
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.standby_attach(vol, force = False)
    cache.stop()
    assert not vol.opened

def test_standby_stop_detached(pyocf_2_ctx):
    ctx = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB
    vol = RamVolume(Size.from_MiB(150))
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.standby_attach(vol, force = False)
    cache.standby_detach()
    assert not vol.opened
    cache.stop()

# verify that force flag is required to attach a standby instance
# on a volume where standby instance had previously been running
def test_standby_attach_force_after_standby(pyocf_2_ctx):
    ctx = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB
    vol = RamVolume(Size.from_MiB(150))
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.standby_attach(vol, force = False)
    cache.standby_detach()
    cache.stop()

    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    with pytest.raises(OcfError) as ex:
        cache.standby_attach(vol, force = False)
    assert ex.value.error_code == OcfErrorCode.OCF_ERR_METADATA_FOUND

    cache.standby_attach(vol, force = True)

def test_standby_attach_force_after_active(pyocf_2_ctx):
    ctx = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB
    vol = RamVolume(Size.from_MiB(150))
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.attach_device(vol)
    cache.stop()
    assert not vol.opened

    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    with pytest.raises(OcfError) as ex:
        cache.standby_attach(vol, force = False)
    assert ex.value.error_code == OcfErrorCode.OCF_ERR_METADATA_FOUND

    cache.standby_attach(vol, force = True)

# standby load from standby cache instance after clean shutdown
def test_standby_load_after_standby_clean_shutdown(pyocf_2_ctx):
    ctx = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB
    vol = RamVolume(Size.from_MiB(150))
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.standby_attach(vol, force = False)
    cache.stop()

    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.standby_load(vol)

    cache.stop()

# standby load from active cache instance after clean shutdown
def test_standby_load_after_active_clean_shutdown(pyocf_2_ctx):
    ctx = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB
    vol = RamVolume(Size.from_MiB(150))
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.attach_device(vol, force = False)
    cache.stop()

    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.standby_load(vol)


# standby load from active cache instance after clean shutdown
def test_standby_load_after_active_dirty_shutdown(pyocf_2_ctx):
    ctx = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB
    vol = RamVolume(Size.from_MiB(150))
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.attach_device(vol, force = False)
    vol.offline()
    with pytest.raises(OcfError) as ex:
        cache.stop()
    assert ex.value.error_code == OcfErrorCode.OCF_ERR_WRITE_CACHE
    vol.online()

    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.standby_load(vol)

    cache.stop()

def test_standby_load_after_standby_dirty_shutdown(pyocf_2_ctx):
    ctx = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB
    vol = RamVolume(Size.from_MiB(150))
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.standby_attach(vol, force = False)
    vol.offline()
    cache.stop()

    vol.online()
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.standby_load(vol)

    cache.stop()

def test_failover_passive_first(pyocf_2_ctx):
    ctx1 = pyocf_2_ctx[0]
    ctx2 = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB

    prim_cache_backend_vol = RamVolume(Size.from_MiB(150))
    core_backend_vol = RamVolume(Size.from_MiB(1))
    sec_cache_backend_vol = RamVolume(Size.from_MiB(150))

    # passive cache with directly on ram disk
    cache2 = Cache(owner=ctx2, cache_mode=mode, cache_line_size=cls)
    cache2.start_cache()
    cache2.standby_attach(sec_cache_backend_vol)

    # volume replicating cache1 ramdisk writes to cache2 cache exported object
    cache2_exp_obj_vol = CacheVolume(cache2)
    cache1_cache_vol = ReplicatedVolume(prim_cache_backend_vol, cache2_exp_obj_vol)

    # active cache
    cache1 = Cache.start_on_device(cache1_cache_vol, ctx1, cache_mode=mode, cache_line_size=cls)
    core = Core(core_backend_vol)
    cache1.add_core(core)

    # some I/O
    r = Rio().target(core).njobs(1).readwrite(ReadWrite.WRITE).size(Size.from_MiB(1)).qd(1).run()

    # capture checksum before simulated active host failure
    md5 = core.exp_obj_md5()

    # offline primary cache volume and stop primary cache to simulate active host
    # failure
    cache1_cache_vol.offline()
    with pytest.raises(OcfError) as ex:
        cache1.stop()
    assert ex.value.error_code == OcfErrorCode.OCF_ERR_WRITE_CACHE

    # failover
    cache2.standby_detach()
    cache2.standby_activate(sec_cache_backend_vol, open_cores=False)

    # add core explicitly with "try_add" to workaround pyocf limitations
    core = Core(core_backend_vol)
    cache2.add_core(core, try_add=True)

    assert md5 == core.exp_obj_md5()

def write_vol(cc, data):
    comp = OcfCompletion([("error", c_int)])
    io = cc.new_io(cc.get_default_queue(), 0, len(data.get_bytes()), IoDir.WRITE, 0, 0)
    io.set_data(data)
    io.callback = comp.callback
    io.submit()
    comp.wait()

def test_failover_active_first(pyocf_2_ctx):
    ctx1 = pyocf_2_ctx[0]
    ctx2 = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB

    prim_cache_backend_vol = RamVolume(Size.from_MiB(150))
    core_backend_vol = RamVolume(Size.from_MiB(1))

    # active cache
    cache1 = Cache.start_on_device(prim_cache_backend_vol, ctx1, cache_mode=mode, cache_line_size=cls)
    core = Core(core_backend_vol)
    cache1.add_core(core)

    # some I/O
    r = Rio().target(core).njobs(1).readwrite(ReadWrite.WRITE).size(Size.from_MiB(1)).qd(1).run()

    # capture checksum before simulated active host failure
    data_md5 = core.exp_obj_md5()

    prim_cache_backend_vol.offline()

    with pytest.raises(OcfError) as ex:
        cache1.stop()
    assert ex.value.error_code == OcfErrorCode.OCF_ERR_WRITE_CACHE

    # capture a copy of active cache instance data
    data = Data.from_bytes(prim_cache_backend_vol.get_bytes())
    cache_md5 = prim_cache_backend_vol.md5()
    
    # setup standby cache
    sec_cache_backend_vol = RamVolume(Size.from_MiB(150))
    cache2 = Cache(owner=ctx2, cache_mode=mode, cache_line_size=cls)
    cache2.start_cache()
    cache2.standby_attach(sec_cache_backend_vol)

    # standby cache exported object volume
    cache2_exp_obj_vol = CacheVolume(cache2)

    # just to be sure
    assert sec_cache_backend_vol.get_bytes() != prim_cache_backend_vol.get_bytes()

    # write content of active cache volume to passive cache exported obj
    write_vol(cache2, data)

    # TODO: why this doesn't work? OCF calls correct completion, but io.c_end() never
    # gets called
    #assert cache_md5 ==  cache2_exp_obj_vol.md5()

    # volumes should have the same data
    assert sec_cache_backend_vol.get_bytes() == prim_cache_backend_vol.get_bytes()

    # failover
    cache2.standby_detach()
    cache2.standby_activate(sec_cache_backend_vol, open_cores=False)
    core = Core(core_backend_vol)
    cache2.add_core(core, try_add=True)

    # check data consistency
    assert data_md5 == core.exp_obj_md5()

#def test_cache_line_size_mismatch_standby_load(pyocf_2_ctx):


