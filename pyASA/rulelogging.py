from enum import Enum
from pyASA.baseconfigobject import BaseConfigObject


class LogLevel(Enum):
    DEFAULT = "Default"
    DISABLE = "Disabled"
    EMERGENCIES = "Emergencies"
    ALERTS = "Alerts"
    CRITICAL = "Critical"
    ERRORS = "Errors"
    WARNINGS = "Warnings"
    NOTIFICATIONS = "Notifications"
    INFORMATIONAL = "Informational"
    DEBUGGING = "Debugging"

    def to_cli(self):
        if self.value == "Disabled":
            return "disable"
        elif self.value == "Default":
            return self.value
        else:
            return self.value.lower()

    @classmethod
    def from_cli(cls, line: str) -> object:
        if line == "disable":
            return LogLevel.DISABLE
        else:
            return LogLevel[line.upper()]


class RuleLogging(BaseConfigObject):
    def __init__(self, level: LogLevel = LogLevel.DEFAULT, interval: int = 300):
        self._interval = 300
        self._level = LogLevel.DEFAULT

        self.interval = interval
        self.level = level

    @property
    def interval(self):
        return self._interval

    @interval.setter
    def interval(self, value: int):
        if isinstance(value, int):
            if 1 <= value <= 600:
                self._interval = int(value)
            else:
                raise ValueError("Interval must be in range 1..600 seconds")
        else:
            raise ValueError(f"{type(value)} is not a valid argument type")

    @property
    def level(self):
        return self._level

    @level.setter
    def level(self, level: [LogLevel, str]):
        if isinstance(level, LogLevel):
            self._level = level
        elif isinstance(level, str):
            try:
                self._level = LogLevel(level)
            except:
                raise ValueError(f"{level} is not a valid argument")
        else:
            raise ValueError(f"{type(level)} is not a valid argument type")

    @classmethod
    def from_dict(cls, data: dict) -> object:
        return cls(LogLevel(data["logStatus"].capitalize()), data["logInterval"])

    def to_cli(self) -> str:
        return f"log {self.level.to_cli()} interval {self.interval}"

    def to_dict(self) -> dict:
        return {"logStatus": self._level.value, "logInterval": self._interval}

    def __eq__(self, other):
        if isinstance(other, RuleLogging):
            return self.level == other.level and self.interval == other.interval
        elif isinstance(other, str):
            return self.to_json() == other
        elif isinstance(other, dict):
            return self.to_dict() == other
        else:
            return False

    @classmethod
    def from_cli(cls, interval: int, level: str) -> object:
        return cls(interval, LogLevel.from_cli(level))
