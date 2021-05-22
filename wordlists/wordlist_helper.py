# Just make it easy to get files from this directory
import os

def get_file(default="subdomains"):
    MY_PATH = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(MY_PATH, default)
