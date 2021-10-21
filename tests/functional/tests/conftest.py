#
# Copyright(c) 2019-2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

import os
import sys
import pytest
import gc

sys.path.append(os.path.join(os.path.dirname(__file__), os.path.pardir))
from pyocf.types.logger import LogLevel, DefaultLogger, BufferLogger
from pyocf.types.volume import get_volume_classes
from pyocf.types.ctx import OcfCtx


def pytest_configure(config):
    sys.path.append(os.path.join(os.path.dirname(__file__), os.path.pardir))


@pytest.fixture()
def pyocf_ctx():
    c = OcfCtx.with_defaults(DefaultLogger(LogLevel.WARN))
    for vol in get_volume_classes():
        vol.register_volume_type(c)
    yield c
    c.exit()
    gc.collect()


@pytest.fixture()
def pyocf_ctx_log_buffer():
    logger = BufferLogger(LogLevel.DEBUG)
    c = OcfCtx.with_defaults(logger)
    for vol in get_volume_classes():
        vol.register_volume_type(c)
    yield logger
    c.exit()
    gc.collect()

@pytest.fixture()
def pyocf_2_ctx():
    c1 = OcfCtx.with_defaults(DefaultLogger(LogLevel.WARN, "Ctx1"))
    c2 = OcfCtx.with_defaults(DefaultLogger(LogLevel.WARN, "Ctx2"))
    for vol in get_volume_classes():
        print("reg vol 1 c 1")
        vol.register_volume_type(c1)
        print("reg vol 1 c 2")
        vol.register_volume_type(c2)
    yield [c1, c2]
    c1.exit()
    c2.exit()
    gc.collect()
