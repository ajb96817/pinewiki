
class SiteConfig:
  def __init__(self, d):
    for key, value in d.items():
      setattr(self, key, value)

  def feature_enabled(self, feature_name):
    return feature_name in self.enabled_features


site_config = SiteConfig({
  'enabled_features': {
    'start', 'files', 'chat', 'recent_changes',
    'check_in', 'calendar', 'journal'
  },
  
  'sitename': 'pinewiki',

  'root_dir': '/var/www/pinewiki',

  # TODO: 'favicon'

  # Optional "theme" CSS file, in addition to the base wiki.css
  'extra_css': None, # 'journal.css',

  # Secret key for Flask user authentication
  'secret_key': 'ueahrucahrou',

  'redis': {
    'host': 'localhost',
    'port': 6379
  }
})

