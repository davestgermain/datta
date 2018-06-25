#!/usr/bin/python
# -*- coding: utf-8 -*-

from werkzeug.exceptions import HTTPException
from flask import request, current_app


class WikiError(HTTPException):
    """Base class for all error pages."""
    # def __init__(self, message=''):
    #     wiki = current_app
    #     html = ''
    #     # with wiki.app_context():
    #     #     context = {
    #     #         '_': wiki.gettext,
    #     #         'wiki': wiki,
    #     #         'code': self.code,
    #     #         'name': self.name,
    #     #         'description': self.get_description(),
    #     #         'title': self.name,
    #     #         'request': request,
    #     #         'url': request.get_url,
    #     #         'download_url': request.get_download_url,
    #     #         'config': wiki.config,
    #     #     }
    #     #     template = wiki.jinja_env.get_template('error.html')
    #     #     html = template.stream(**context)
    #     HTTPException.__init__(self, html)


class BadRequest(WikiError):
    code = 400


class ForbiddenErr(WikiError):
    code = 403


class NotFoundErr(WikiError):
    code = 404


class RequestEntityTooLarge(WikiError):
    code = 413


class RequestURITooLarge(WikiError):
    code = 414


class UnsupportedMediaTypeErr(WikiError):
    code = 415


class NotImplementedErr(WikiError):
    code = 501


class ServiceUnavailableErr(WikiError):
    code = 503
