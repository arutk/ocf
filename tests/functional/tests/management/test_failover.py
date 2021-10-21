from pyocf.types.cache import (
    Cache,
    CacheMode,
    MetadataLayout,
    CleaningPolicy,
)
from pyocf.types.volume import RamVolume
from pyocf.types.volume_ocf import OcfVolume
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
    prim_cache_vol = RamVolume(Size.from_MiB(35))
    prim_core_vol = RamVolume(Size.from_MiB(100))
    sec_cache_vol = RamVolume(Size.from_MiB(35))
    sec_core_vol = RamVolume(Size.from_MiB(100))

    cache = Cache.start_on_device(prim_cache_vol, ctx1, cache_mode=mode, cache_line_size=cls)



