"""
P2P Secure Messaging - A secure peer-to-peer messaging system with end-to-end encryption
"""

__version__ = "0.1.0"
__author__ = "Your Name"
__email__ = "your.email@example.com"

# Core modules
from .crypto import *
from .encryption import *
from .network import *
from .cli import *

__all__ = [
    "__version__",
    "__author__", 
    "__email__",
] 