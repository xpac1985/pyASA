import json
from abc import ABC, abstractmethod


class BaseConfigObject(ABC):
    """
    Base config object class which implements some basic functionality for all other derived classes.
    Other methods must be individually implemented by derived class.
    """

    @classmethod
    @abstractmethod
    def from_dict(cls, data: dict) -> "BaseConfigObject":
        raise NotImplementedError()

    @abstractmethod
    def to_cli(self) -> str:
        raise NotImplementedError()

    @abstractmethod
    def to_dict(self) -> dict:
        raise NotImplementedError()

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def __repr__(self) -> str:
        return self.to_json()
