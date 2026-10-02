"""Four bounded offline Nginx policies, never a deployment safety verdict."""
from .review import review_config
from .report import Limits
__version__ = '0.1.1'
__all__ = ['Limits', 'review_config']
