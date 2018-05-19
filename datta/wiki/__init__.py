from .cache import CachedWiki as Wiki
from hatta import WikiConfig

# also fixup hatta page imports
from hatta import page
from PIL import Image
page.Image = Image
