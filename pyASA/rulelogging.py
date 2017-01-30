from enum import Enum
from typing import Union, Dict, Any

from pyASA.baseconfigobject import BaseConfigObject


class LogLevel(Enum):
    """
    Class used to represent log levels used for rule objects
    """
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

    def to_cli(self) -> str:
        """
        Convert LogLevel to string corresponding to CLI style log level.

        Returns:
            log level string as used on CLI
        """
        if self.value == "Disabled":
            return "disable"
        elif self.value == "Default":
            return self.value
        else:
            return self.value.lower()

    @classmethod
    def from_cli(cls, line: str) -> "LogLevel":
        """
        Return LogLevel from CLI style string.

        Returns:
            LogLevel matching CLI string
        """
        return LogLevel[line.upper()]


class RuleLogging(BaseConfigObject):
    """
    Class representing logging settings for ACL rules
    """

    def __init__(self, level: LogLevel = LogLevel.DEFAULT, interval: int = 300):
        self._interval = 300
        self._level = LogLevel.DEFAULT

        self.interval = interval
        self.level = level

    @property
    def interval(self) -> int:
        """
        Return/set log interval value.

        Returns:
            log interval value
        """
        return self._interval

    @interval.setter
    def interval(self, interval: int):
        if isinstance(interval, int):
            if 1 <= interval <= 600:
                self._interval = int(interval)
            else:
                raise ValueError("Interval must be in range 1..600 seconds")
        else:
            raise ValueError(f"{type(interval)} is not a valid argument type")

    @property
    def level(self) -> LogLevel:
        """
        Return/set log level value.

        Returns:
            log interval value
        """
        return self._level

    @level.setter
    def level(self, level: Union[LogLevel, str]):
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
    def from_dict(cls, data: Dict[str, Any]) -> "RuleLogging":
        """
        Uses a dictionary representation of a rule logging setting  to create a rule logging object.

        Args:
            data: dict to create rule logging object from, structured like the JSON responses from the API

        Returns:
            rule logging object equivalent to the provided data
        """
        return cls(LogLevel(data["logStatus"].capitalize()), data["logInterval"])

    def to_cli(self) -> str:
        """
        Return a CLI-style representation of the rule logging setting.

        Returns:
            string containing CLI-style rule logging setting
        """

        if self.level in [LogLevel.DEFAULT, LogLevel.DISABLE]:
            return f"{self.level.to_cli()}"
        else:
            return f"log {self.level.to_cli()} interval {self.interval}"

    def to_dict(self) -> Dict[str, Any]:
        """
        Return rule logging data as dict representation in API JSON style.

        Returns:
            dict of rule logging setting values that can be easily converted to JSON for use with API
        """
        return {"logStatus": self._level.value, "logInterval": self._interval}

    def __eq__(self, other) -> bool:
        if isinstance(other, RuleLogging):
            return self.level == other.level and self.interval == other.interval
        elif isinstance(other, str):
            return self.to_json() == other
        elif isinstance(other, dict):
            return self.to_dict() == other
        else:
            return False

    @classmethod
    def from_cli(cls, interval: int, level: str) -> "RuleLogging":
        """
        Return rule logging object from CLI style string.

        Returns:
            RuleLogging object matching CLI string
        """
        return cls(interval, LogLevel.from_cli(level))
