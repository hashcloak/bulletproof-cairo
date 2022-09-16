from .pippenger import Pippenger
from src.group import EC
from .curve import CURVE as _CURVE


PipCURVE = Pippenger(EC(_CURVE))
CURVE = _CURVE

__all__ = ["Pippenger", "EC", "PipCURVE", "CURVE"]
