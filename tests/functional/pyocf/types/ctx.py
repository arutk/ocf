#
# Copyright(c) 2019-2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

from ctypes import c_void_p, Structure, c_char_p, cast, pointer, byref, c_int
import weakref

from .logger import LoggerOps, Logger
from .data import DataOps, Data
from .cleaner import CleanerOps, Cleaner
from .shared import OcfError
from ..ocf import OcfLib
from .queue import Queue

import pdb

class OcfCtxOps(Structure):
    _fields_ = [
        ("data", DataOps),
        ("cleaner", CleanerOps),
        ("logger", LoggerOps),
    ]


class OcfCtxCfg(Structure):
    _fields_ = [("name", c_char_p), ("ops", OcfCtxOps), ("logger_priv", c_void_p)]


class OcfCtx:
    default = None

    def __init__(self, lib, name, logger, data, cleaner):
        self.logger = logger
        self.data = data
        self.cleaner = cleaner
        self.ctx_handle = c_void_p()
        self.lib = lib
        self.caches = []
        self.registered_volume_types = []

        self.cfg = OcfCtxCfg(
            name=name,
            ops=OcfCtxOps(
                data=self.data.get_ops(),
                cleaner=self.cleaner.get_ops(),
                logger=logger.get_ops(),
            ),
            logger_priv=cast(pointer(logger.get_priv()), c_void_p),
        )

        result = self.lib.ocf_ctx_create(byref(self.ctx_handle), byref(self.cfg))
        if result != 0:
            raise OcfError("Context initialization failed", result)

        if self.default is None or self.default() is None:
            type(self).default = weakref.ref(self)

    @classmethod
    def with_defaults(cls, logger):
        return cls(
            OcfLib.getInstance(),
            b"PyOCF default ctx",
            logger,
            Data,
            Cleaner,
        )

    @classmethod
    def get_default(cls):
        if cls.default is None or cls.default() is None:
            raise Exception("No context instantiated yet")

        return cls.default()

    def register_volume_type(self, vol_id, props):
        result = self.lib.ocf_ctx_register_volume_type(
            self.ctx_handle, vol_id, props)
        if result != 0:
            raise OcfError("Volume type registration failed", result)

    def unregister_volume_type(self, type_id):
        self.lib.ocf_ctx_unregister_volume_type(
            self.ctx_handle, type_id
        )
        self.registered_volume_types += [type_id]

    def cleanup_volume_types(self):
        for vol_type in self.registered_volume_types:
            self.unregister_volume_type(vol_type)

    def stop_caches(self):
        for cache in self.caches[:]:
            cache.stop()

    def exit(self):
        self.stop_caches()
        self.cleanup_volume_types()

        self.lib.ocf_ctx_put(self.ctx_handle)

        # self.cfg = None
        # self.logger = None
        # self.data = None
        # self.cleaner = None
        # Queue._instances_ = {}
        # Volume._instances_ = {}
        # Data._instances_ = {}
        # Logger._instances_ = {}



lib = OcfLib.getInstance()
lib.ocf_mngt_cache_get_by_name.argtypes = [c_void_p, c_void_p, c_void_p]
lib.ocf_mngt_cache_get_by_name.restype = c_int
