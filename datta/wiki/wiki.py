# -*- coding: utf-8 -*-
import gettext
import os
import sys
import flask
from flask.config import ConfigAttribute
from werkzeug import routing, url_quote, url_unquote

import datta.wiki.views
from .response import WikiResponse
from .dbstorage import WikiStorage
from .search import WikiSearch
from .cache import DBCacheManager
from .config import MultiConfig



class WikiTitleConverter(routing.PathConverter):
    """Behaves like the path converter, but doesn't match the "+ pages"."""

    def to_url(self, value):
        return url_quote(value.strip(), self.map.charset, safe="/")

    regex = '([^+%]|%[^2]|%2[^Bb]).*'


class WikiAllConverter(routing.BaseConverter):
    """Matches everything."""

    regex = '.*'



def init_gettext(language):
    if language is not None:
        try:
            translation = gettext.translation(
                'datta.wiki',
                'locale',
                languages=[language],
            )
        except IOError:
            translation = gettext.translation(
                'datta.wiki',
                fallback=True,
                languages=[language],
            )
    else:
        translation = gettext.translation('datta.wiki', fallback=True)
    return translation


def init_template(translation, template_path):
    import jinja2
    loaders = [jinja2.PackageLoader('datta.wiki', 'templates')]

    if template_path is not None:
        loaders.insert(0, jinja2.FileSystemLoader(os.path.abspath(template_path)))

    template_env = jinja2.Environment(
        extensions=['jinja2.ext.i18n'],
        loader=jinja2.ChoiceLoader(loaders),
    )
    template_env.autoescape = True
    template_env.install_gettext_translations(translation, True)
    return template_env


class WikiRequest(flask.Request):
    def get_author(self):
        """Try to guess the author name. Use IP address as last resort."""

        try:
            cookie = url_unquote(self.cookies.get("author", ""))
        except UnicodeError:
            cookie = None
        try:
            auth = url_unquote(self.environ.get('REMOTE_USER', ""))
        except UnicodeError:
            auth = None
        author = (self.form.get("author") or cookie or auth or
                  self.remote_addr)
        return author


class Wiki(flask.Flask):
    """
    The main class of the wiki, handling initialization of the whole
    application and most of the logic.
    """
    storage_class = WikiStorage
    index_class = WikiSearch
    request_class = WikiRequest
    response_class = WikiResponse
    config_class = MultiConfig
    
    menu_page = ConfigAttribute('MENU_PAGE')
    front_page = ConfigAttribute('FRONT_PAGE')
    logo_page = ConfigAttribute('LOGO_PAGE')
    locked_page = ConfigAttribute('LOCKED_PAGE')
    icon_page = ConfigAttribute('ICON_PAGE')
    alias_page = ConfigAttribute('ALIAS_PAGE')
    help_page = ConfigAttribute('HELP_PAGE')
    read_only = ConfigAttribute('READ_ONLY')
    site_name = ConfigAttribute('SITE_NAME')
    fallback_url = ConfigAttribute('FALLBACK_URL')
    math_url = ConfigAttribute('MATH_URL')
    pygments_style = ConfigAttribute('PYGMENTS_STYLE')
    recaptcha_public_key = ConfigAttribute('RECAPTCHA_PUBLIC_KEY')
    recaptcha_private_key = ConfigAttribute('RECAPTCHA_PRIVATE_KEY')
    page_charset = 'utf8'
    unix_eol = True


    def __init__(self, dsn='lmdb:///tmp/wiki'):
        flask.Flask.__init__(self, 'datta.wiki')
        self.dsn = dsn
        print('dsn is', self.dsn)


        # self.language = config.get('language')
        self.language = None
        translation = init_gettext(self.language)
        self.gettext = translation.gettext

        # self.template_path = config.get('template_path')
        self.jinja_options['extensions'].append('jinja2.ext.i18n')
        
        self.jinja_env.install_gettext_translations(translation, True)
        # self.template_env = init_template(translation, self.template_path)

        self.storage = self.storage_class(
            dsn,
            self.page_charset,
            self.gettext,
            self.unix_eol,
        )

        self.config.from_storage(self.storage)
        self.cache = DBCacheManager(self)
        self.cache.initialize()

        
        self.index = self.index_class(self.cache, self.language, self.storage)
        self.url_map.converters['title'] = WikiTitleConverter
        self.url_map.converters['all'] = WikiAllConverter
        self.register_blueprint(datta.wiki.views.bp)
        self.before_first_request(self._startup)
        self.before_request(self._config_switcher)
        self._last_host = None

    def _startup(self):
        # self.storage.set_wiki()
        # self.index.update(self)
        self._url_adapter = self.create_url_adapter(flask.request)

    def _config_switcher(self):
        host = flask.request.host
        if host != self._last_host:
            self.config.switch_config(host)
            self.storage.set_wiki(self.config.get('PAGE_PATH', host))
            self.index.update(self)
            self._last_host = host

    def render_template(self, template_name, **context):
        return flask.render_template(template_name, **context)

    def get_url(self, title=None, view=None, method='GET',
                external=False, **kw):
        if view is None:
            view = 'view'
        view = 'datta.wiki.%s' % view
        if title is not None:
            kw['title'] = title.strip()
        # kw['force_external'] = external
        # kw['method'] = method
        # url = flask.url_for(view, **kw)
        # print(flask.url_for(view, **kw))
        url = self._url_adapter.build(view, kw, method=method,
                                               force_external=external)
        return url

    def get_download_url(self, title):
        return self.get_url(title, 'download')

    def refresh(self):
        """Make sure we have the latest revision of storage."""
        pass
        # storage_rev = self.storage.repo_revision()
        # index_rev = self.index.get_last_revision()
        # if storage_rev < index_rev:
        #     self.storage.reopen()
