from pyocf.types.cache import (
    Cache,
    CacheMode,
    MetadataLayout,
    CleaningPolicy,
)
from pyocf.types.core import Core
from pyocf.types.volume import RamVolume
from pyocf.types.volume_cache import CacheVolume
from pyocf.types.volume_replicated import ReplicatedVolume
from pyocf.types.shared import (
    OcfError,
    OcfCompletion,
    CacheLines,
    CacheLineSize,
    SeqCutOffPolicy,
)
from pyocf.utils import Size
from pyocf.rio import Rio, ReadWrite

def test_setup_failover(pyocf_2_ctx):
    ctx1 = pyocf_2_ctx[0]
    ctx2 = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB

    prim_cache_backend_vol = RamVolume(Size.from_MiB(50))
    core_backend_vol = RamVolume(Size.from_MiB(1))
    sec_cache_backend_vol = RamVolume(Size.from_MiB(50))

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
    cache1.stop()

    # failover
    cache2.standby_detach()
    cache2.standby_activate(sec_cache_backend_vol, open_cores=False)

    # add core explicitly with "try_add" to workaround pyocf limitations
    core = Core(core_backend_vol)
    cache2.add_core(core, try_add=True)
    
    assert md5 == core.exp_obj_md5()
