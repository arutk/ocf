import pytest
from datetime import timedelta

from pyocf.types.volume import RamVolume
from pyocf.types.cache import Cache
from pyocf.types.queue import Queue
from pyocf.utils import Size
from pyocf.types.shared import CacheLineSize
from pyocf.types.ctx import OcfCtx
from pyocf.rio import Rio, ReadWrite

@pytest.mark.parametrize("cacheline_size", CacheLineSize)
def test_test_standby_io(pyocf_ctx, cacheline_size):
    num_jobs = 8
    qd = 8
    runtime = 30

    vol_size = Size.from_MiB(20)
    cache_vol = RamVolume(vol_size)

    cache = Cache(owner = OcfCtx.get_default(), cache_line_size=cacheline_size)

    cache.start_cache(init_default_io_queue = False)

    for i in range(num_jobs):
        cache.add_io_queue(f"io-queue-{i}")

    cache.standby(cache_vol)

    r = (
            Rio()
            .target(cache)
            .njobs(num_jobs)
            .readwrite(ReadWrite.RANDWRITE)
            .size(vol_size)
            .io_size(Size.from_GiB(100))
            .bs(Size.from_KiB(4))
            .qd(qd)
            .time(timedelta(seconds = runtime))
            .time_based()
            .run(cache.io_queues)
        )
 


