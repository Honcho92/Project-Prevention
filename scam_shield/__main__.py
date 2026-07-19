"""Allow `python -m scam_shield ...`."""
from .cli import main
import sys
sys.exit(main())
