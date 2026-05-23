import importlib.metadata

try:
    __version__ = importlib.metadata.version("provablyfine")
except importlib.metadata.PackageNotFoundError:
    # Package not installed
    __version__ = "0.0.0-dev"
