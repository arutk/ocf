#
# Copyright(c) 2019-2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
from ctypes import c_void_p, CDLL
import inspect
import os


class OcfLib:
    __lib__ = None

    @classmethod
    def getInstance(cls):
        ddd = os.path.dirname(inspect.getfile(inspect.currentframe()))
        ppp = os.path.join(ddd, "libocf.so")
        if cls.__lib__ is None:
            # https://stackoverflow.com/questions/58631512/pywin32-and-python-3-8-0/58632354#58632354
            lib = CDLL(ppp, winmode = 0)
            lib.ocf_volume_get_uuid.restype = c_void_p
            lib.ocf_volume_get_uuid.argtypes = [c_void_p]

            lib.ocf_core_get_front_volume.restype = c_void_p
            lib.ocf_core_get_front_volume.argtypes = [c_void_p]

            cls.__lib__ = lib

        return cls.__lib__
