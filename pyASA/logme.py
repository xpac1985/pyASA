import functools
import logging


class LogMe(object):
    """
    NOT IN USE due to some bugs

    Utility class returning a decorator that can be attached to functions and methods.

    Causes every decorated function/method to log a debug message when it's started and when it's finished
    """

    def __init__(self, f):
        self.f = f
        self.logger = logging.getLogger("pyASA")

    def __call__(self, *args, **kwargs):
        if type(args[0]) is type:
            self.logger.debug(
                f"Starting {args[0].__name__}.{self.f.__name__}() with {len(args)} args, {len(kwargs)} kwargs")
        else:
            self.logger.debug(
                f"Starting {args[0].__class__.__name__}.{self.f.__name__}() with {len(args)} args, {len(kwargs)} kwargs")
        if args[0] is None:
            result = self.f(*args[1:], **kwargs)
        else:
            result = self.f(*args, **kwargs)
        if type(args[0]) is type:
            self.logger.debug(f"Finished {args[0].__name__}.{self.f.__name__}()")
        else:
            self.logger.debug(f"Finished {args[0].__class__.__name__}.{self.f.__name__}()")
        return result

    def __get__(self, obj, objtype):
        return functools.partial(self.__call__, obj)
