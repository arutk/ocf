from .core import Core
from .volume_exp_obj import ExpObjVolume
from pyocf.types.io import IoDir

class CoreVolume(ExpObjVolume):
    def __init__(self, core, uuid = None):
        super().__init__(core, uuid)
        self.core = core

    def get_stats(self):
        stats = self.core.get_stats()["block"]
        return {IoDir.WRITE: stats["volume_wr"]["value"],
                IoDir.READ: stats["volume_rd"]["value"]}

    def reset_stats(self):
        self.core.reset_stats()

    def md5(self):
        return self.core.exp_obj_md5()
