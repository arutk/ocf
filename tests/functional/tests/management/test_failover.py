from pyocf.types.cache import (
    Cache,
    CacheMode,
    MetadataLayout,
    CleaningPolicy,
)
from pyocf.types.core import Core
from pyocf.types.volume import RamVolume
from pyocf.types.volume_ocf import CoreVolume
from pyocf.types.volume_replicated import ReplicatedVolume
from pyocf.types.shared import (
    OcfError,
    OcfCompletion,
    CacheLines,
    CacheLineSize,
    SeqCutOffPolicy,
)
from pyocf.utils import Size

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
    cache2 = Cache.start_on_device(sec_cache_backend_vol, ctx2, cache_mode=mode, cache_line_size=cls)
    core2 = Core.using_device(sec_core_backend_vol)
    cache2.add_core(core2)

    # volume replicating core1 ramdisk writes to cache2 exported object
    cache2_exp_obj_vol = CoreVolume(core2)
    cache1_core_vol = ReplicatedVolume(prim_core_backend_vol, cache2_exp_obj_vol)

    # active cache 
    cache1 = Cache.start_on_device(prim_cache_backend_vol, ctx1, cache_mode=mode, cache_line_size=cls)
    core1 = Core.using_device(cache1_core_vol)
    cache1.add_core(core1)



