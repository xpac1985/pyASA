import logging
import sys

if sys.version_info[0:2] < (3, 6):
    raise RuntimeError('Python 3.6.x or higher is required!')

logger = logging.getLogger("pyASA")
logger.setLevel(logging.WARNING)
logger_console = logging.StreamHandler()
logger_console.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
logger.addHandler(logger_console)
