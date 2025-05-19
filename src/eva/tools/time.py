from datetime import datetime


def get_current_date():
    """
    Get the current date in YYYY-MM-DD format.
    :return: Current date as a string
    """
    return datetime.now().strftime("%Y-%m-%d")

def get_current_time():
    """
    Get the current time in HH:MM:SS format.
    :return: Current time as a string
    """
    return datetime.now().strftime("%H:%M:%S")
