import functools
import logging


class LogMe(object):
    def __init__(self, f):
        self.f = f
        self.logger = logging.getLogger("pyASA")

    def __call__(self, *args, **kwargs):
        self.logger.debug(f"Starting {args[0].__class__.__name__}.{self.f.__name__}() with {len(args)} args, {len(kwargs)} kwargs")
        self.f(*args, **kwargs)
        self.logger.debug(f"Finished {args[0].__class__.__name__}.{self.f.__name__}()")

    def __get__(self, obj, objtype):
        return functools.partial(self.__call__, obj)
