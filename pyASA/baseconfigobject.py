import json
from abc import ABC, abstractmethod


class BaseConfigObject(ABC):
    @classmethod
    @abstractmethod
    def from_dict(cls, data: dict):
        raise NotImplementedError()

    @abstractmethod
    def to_dict(self) -> dict:
        raise NotImplementedError()

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def __repr__(self):
        return self.to_json()
