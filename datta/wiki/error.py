#!/usr/bin/python
# -*- coding: utf-8 -*-

from werkzeug.exceptions import HTTPException
from flask import request, current_app


class WikiError(HTTPException):
    """Base class for all error pages."""
    def get_body(self, environ):
        wiki = current_app
        context = {
            'wiki': wiki,
            'code': self.code,
            'name': self.name,
            'description': self.get_description(environ),
            'title': self.name,
            'request': request,
            'url': wiki.get_url,
            'download_url': wiki.get_download_url,
            'config': wiki.config,
        }
        return wiki.render_template('error.html', **context)


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
