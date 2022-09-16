from abc import ABC, abstractmethod

from src.utils.utils import ModP
from fastecdsa.curve import Curve
from fastecdsa.point import Point


class Group(ABC):
    def __init__(self, unit, order):
        self.unit = unit
        self.order = order

    @abstractmethod
    def mult(self, x, y):
        pass

    def square(self, x):
        return self.mult(x, x)


class MultIntModP(Group):
    def __init__(self, p, order):
        Group.__init__(self, ModP(1, p), order)

    def mult(self, x, y):
        return x * y


class EC(Group):
    def __init__(self, curve: Curve):
        Group.__init__(self, curve.G.IDENTITY_ELEMENT, curve.q)

    def mult(self, x, y):
        return x + y

    def elem_to_cairo(p: Point) -> list[int]:
        """
            Take in an ec point and convert it into a cairo struct of type `EcPoint`
            struct EcPoint:
                member x : felt
                member y : felt
            end
            @return a list of 2 felt elements
        """
        return [p.x, p.y]
        
