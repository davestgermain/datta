# -*- coding: utf-8 -*-

from flask.config import Config
from werkzeug.datastructures import ImmutableDict
import json
import os.path

DEFAULTS = ImmutableDict({
    'MENU_PAGE': 'Menu',
    'FRONT_PAGE': 'Home',
    'LOGO_PAGE': 'logo.png',
    'LOCKED_PAGE': 'Locked',
    'ALIAS_PAGE': 'Alias',
    'HELP_PAGE': 'Help',
    'ICON_PAGE': None,
    'READ_ONLY': False,
    'SITE_NAME': 'Datta Wiki',
    'FALLBACK_URL': None,
    'MATH_URL': 'http://www.mathtran.org/cgi-bin/mathtran?tex=',
    'PYGMENTS_STYLE': 'tango',
    'RECAPTCHA_PUBLIC_KEY': None,
    'RECAPTCHA_PRIVATE_KEY': None,
})


class MultiConfig(Config):
    def from_storage(self, storage):
        fs = storage.fs
        path = '/.config/wiki/'
        configs = {
            'DEFAULT': dict(DEFAULTS)
        }
        for fp in fs.listdir(path, open_files=True):
            domain = os.path.basename(fp.path)
            conf = dict(DEFAULTS)
            with fp:
                conf.update(json.load(fp))
            configs[domain] = conf
        self.configs = configs
        self.current_domain = 'DEFAULT'
        self.update(configs[self.current_domain])

    def switch_config(self, domain):
        if domain != self.current_domain:
            self.update(self.configs.get(domain, self.configs['DEFAULT']))
            self.current_domain = domain

