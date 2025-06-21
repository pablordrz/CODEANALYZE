import logging
import sys
from logging.handlers import TimedRotatingFileHandler

def setup_logger():
    # Create a logger
    logger = logging.getLogger('my_app_logger')
    logger.setLevel(logging.INFO)

    # Create a file handler that rotates daily
    handler = TimedRotatingFileHandler('app.log', when='midnight', interval=1, backupCount=7, encoding='utf-8')
    handler.setLevel(logging.INFO)

    # Create a formatter and set it for the handler
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    # Add the handler to the logger
    logger.addHandler(handler)

    # Also log to console
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    return logger

# Create a logger instance
logger = setup_logger() 