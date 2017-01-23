import logging

logger = logging.getLogger("pyASA")
logger.setLevel(logging.WARNING)
logger_console = logging.StreamHandler()
logger_console.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
logger.addHandler(logger_console)
