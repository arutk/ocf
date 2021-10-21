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

import pdb

def test_setup_failover(pyocf_2_ctx):
    ctx1 = pyocf_2_ctx[0]
    ctx2 = pyocf_2_ctx[1]
    mode = CacheMode.WO
    cls = CacheLineSize.LINE_4KiB

    prim_cache_backend_vol = RamVolume(Size.from_MiB(35))
    prim_core_backend_vol = RamVolume(Size.from_MiB(100))
    sec_cache_backend_vol = RamVolume(Size.from_MiB(35))
    sec_core_backend_vol = RamVolume(Size.from_MiB(100))

    # passive cache with core directly on ram disk
    cache2 = Cache(owner=ctx2, cache_mode=mode, cache_line_size=cls)
    cache2.start_cache()
    cache2.standby(sec_cache_backend_vol)

    #core2 = Core.using_device(sec_core_backend_vol)
    #cache2.add_core(core2)

    # volume replicating cache1 ramdisk writes to cache2 cache exported object
    cache2_exp_obj_vol = CacheVolume(cache2)
    cache1_cache_vol = ReplicatedVolume(prim_cache_backend_vol, cache2_exp_obj_vol)

    # active cache 
    pdb.set_trace()
    cache1 = Cache.start_on_device(cache1_cache_vol, ctx1, cache_mode=mode, cache_line_size=cls)
    core1 = Core.using_device(prim_core_backend_vol)
    cache1.add_core(core1)



