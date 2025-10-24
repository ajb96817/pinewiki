
import sys
from site_config import site_config

#sys.path.insert(0, '/var/www/pinewiki')
sys.path.insert(0, site_config.root_dir)

from pinewiki import app as application
