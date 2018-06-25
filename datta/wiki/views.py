# -*- coding: utf-8 -*-

import itertools
import re
import datetime
import os
import tempfile
import pkgutil
from flask import Blueprint, request, current_app
import werkzeug

captcha = None
try:
    from recaptcha.client import captcha
except ImportError:
    pass
pygments = None
try:
    import pygments
except ImportError:
    pass

from datta.wiki import page, error, parser, response



bp = Blueprint('datta.wiki', 'datta.wiki')


def _serve_default(request, title, content=None, mime=None):
    """Some pages have their default content."""

    if title in current_app.storage:
        return download(request, title)
    if content is None:
        content = pkgutil.get_data('datta.wiki', os.path.join('static', title))
    mime = mime or 'application/octet-stream'
    resp = response.WikiResponse(
        content,
        content_type=mime,
    )
    resp.set_etag('/%s/-1' % title)
    resp.make_conditional(request)
    return resp




@bp.route('/+history/<title:title>/<int:rev>')
def revision(title, rev):
    _ = current_app.gettext
    text = current_app.storage.revision_text(title, rev)
    link = werkzeug.html.a(werkzeug.html(title),
                           href=current_app.get_url(title))
    content = [
        werkzeug.html.p(
            werkzeug.html(
                _('Content of revision %(rev)d of page %(title)s:'))
            % {'rev': rev, 'title': link}),
        werkzeug.html.pre(werkzeug.html(text)),
    ]
    special_title = _('Revision of "%(title)s"') % {'title': title}
    p = page.get_page(request, title)
    html = p.template('page_special.html', content=content,
                         special_title=special_title)
    resp = response.response(request, title, html, rev=rev, etag='/old')
    return resp

@bp.route('/+version/')
@bp.route('/+version/<title:title>')
def version(title=None):
    if title is None:
        version = current_app.storage.repo_revision()
    else:
        try:
            version, x, x, x = next(current_app.storage.page_history(title))
        except StopIteration:
            version = 0
    return response.WikiResponse('%d' % version, content_type="text/plain")


@bp.route('/+feed/atom')
@bp.route('/+feed/rss')
def atom():
    _ = current_app.gettext
    feed = werkzeug.contrib.atom.AtomFeed(current_app.site_name,
        feed_url=request.url,
        url=request.adapter.build('view', force_external=True),
        subtitle=_('Track the most recent changes to the wiki '
                   'in this feed.'))
    history = itertools.islice(current_app.storage.history(), None, 10, None)
    unique_titles = set()
    for title, rev, date, author, comment in history:
        if title in unique_titles:
            continue
        unique_titles.add(title)
        if rev > 0:
            url = request.adapter.build('diff', {
                'title': title,
                'from_rev': rev - 1,
                'to_rev': rev,
            }, force_external=True)
        else:
            url = request.adapter.build('view', {
                'title': title,
            }, force_external=True)
        feed.add(title, comment, content_type="text", author=author,
                 url=url, updated=date)
    rev = current_app.storage.repo_revision()
    resp = response.response(request, 'atom', feed.generate(),
                                       '/+feed', 'application/xml', rev)
    resp.make_conditional(request)
    return resp


@bp.route('/+render/<title:title>')
def render(title):
    """Serve a thumbnail or otherwise rendered content."""

    p = page.get_page(request, title)
    try:
        cache_filename, cache_mime = p.render_mime()
        render_func = p.render_cache
        if not current_app.cache:
            raise NotImplementedError()
    except (AttributeError, NotImplementedError):
        return download(title)

    cache_key = '/render/%s_%s' % (werkzeug.url_quote(title, safe=''), cache_filename)

    rev, dt, author, comment = current_app.storage.page_meta(title)
    cache_file = current_app.cache.open(cache_key, 'r')
    if (cache_file and dt > cache_file.modified) or not cache_file:
        cache_file = current_app.cache.open(cache_key, 'w')
        try:
            result_file = render_func(cache_file)
        except error.UnsupportedMediaTypeErr:
            return download(title)
        else:
            cache_file = current_app.cache.open(cache_key, 'r')
    resp = response.response(request, title, werkzeug.wrap_file(request.environ, cache_file), '/render', cache_mime,
                             size=cache_file.length)
    resp.direct_passthrough = True
    return resp

@bp.route('/+undo/<title:title>', methods=['POST'])
def undo(title):
    """Revert a change to a page."""

    _ = current_app.gettext

    page.check_lock(current_app, title)
    rev = None
    for key in request.form:
        try:
            rev = int(key)
        except ValueError:
            pass
    author = request.get_author()
    if rev is not None:
        try:
            parent = int(request.form.get("parent"))
        except (ValueError, TypeError):
            parent = None
        current_app.index.update(current_app)
        if rev == 0:
            comment = _('Delete page %(title)s') % {'title': title}
            data = ''
            current_app.storage.delete_page(title, author, comment)
        else:
            comment = _('Undo of change %(rev)d of page %(title)s') % {
                'rev': rev, 'title': title}
            data = current_app.storage.page_revision(title, rev - 1)
            current_app.storage.save_data(title, data, author, comment, parent)
        p = page.get_page(request, title)
        current_app.index.update_page(p, title, data=data)
    url = current_app.get_url(view='history', title=title,
                                method='GET', force_external=True)
    return response.redirect(url, code=303)

@bp.route('/+history/<title:title>')
def history(title):
    """Display history of changes of a page."""

    max_rev = -1
    history = []

    if title not in current_app.storage:
        raise error.NotFoundErr("Page not found.")
    p = page.get_page(request, title)
    make_url = current_app.get_url
    for rev, date, author, comment in current_app.storage.page_history(title):
        if max_rev < rev:
            max_rev = rev
        if rev > 0:
            date_url = make_url(view='diff',
                title=title,
                from_rev=rev - 1,
                to_rev=rev,
            )
        else:
            date_url = make_url(view='revision',
                title=title,
                rev=rev,
            )
        history.append((date, date_url, rev, author, comment))
    html = p.template('history.html', history=history,
                         date_html=page.date_html, parent=max_rev)
    resp = response.response(request, title, html, '/history')
    return resp

@bp.route('/+history/')
def recent_changes():
    """Serve the recent changes page."""

    def _changes_list():
        last = {}
        lastrev = {}
        count = 0
        make_url = current_app.get_url
        for title, rev, date, author, comment in current_app.storage.history():
            if (author, comment) == last.get(title, (None, None)):
                continue
            count += 1
            if count > 100:
                break
            if rev > 0:
                date_url = make_url(view='diff',
                            title=title,
                            from_rev=rev - 1,
                            to_rev=lastrev.get(title, rev),
                )
            elif rev == 0:
                date_url = make_url(view='revision',
                    title=title,
                    rev=rev,
                )
            else:
                date_url = make_url(view='history', title=title)
            last[title] = author, comment
            lastrev[title] = rev

            yield date, date_url, title, author, comment


    p = page.get_page(request, '')
    html = p.template('changes.html', changes=_changes_list(),
                         date_html=page.date_html)
    resp = response.WikiResponse(html, content_type='text/html')
    resp.set_etag('/history/%d' % current_app.storage.repo_revision())
    resp.make_conditional(request)
    return resp

@bp.route('/+history/<title:title>/<int:from_rev>:<int:to_rev>')
def diff(title, from_rev, to_rev):
    """Show the differences between specified revisions."""

    _ = current_app.gettext

    p = page.get_page(request, title)
    build = current_app.get_url
    from_url = build(view='revision', title=title, rev=from_rev)
    to_url = build(view='revision', title=title, rev=to_rev)
    a = werkzeug.html.a
    links = {
        'link1': a(str(from_rev), href=from_url),
        'link2': a(str(to_rev), href=to_url),
        'link': a(werkzeug.html(title), href=current_app.get_url(title)),
    }
    message = werkzeug.html(_(
        'Differences between revisions %(link1)s and %(link2)s '
        'of page %(link)s.')) % links
    diff_content = getattr(p, 'diff_content', None)
    if diff_content:
        from_text = current_app.storage.revision_text(p.title, from_rev)
        to_text = current_app.storage.revision_text(p.title, to_rev)
        content = diff_content(from_text, to_text, message)
    else:
        content = [werkzeug.html.p(werkzeug.html(
            _("Diff not available for this kind of pages.")))]
    special_title = _('Diff for "%(title)s"') % {'title': title}
    html = p.template('page_special.html', content=content,
                        special_title=special_title)
    resp = response.WikiResponse(html, content_type='text/html')
    return resp

@bp.route('/+index')
def all_pages():
    """Show index of all pages in the current_app."""

    _ = current_app.gettext

    p = page.get_page(request, '')
    html = p.template('list.html',
                         pages=sorted(current_app.storage.all_pages()),
                         class_='index',
                         message=_('Index of all pages'),
                         special_title=_('Page Index'))
    resp = response.WikiResponse(html, content_type='text/html')
    resp.set_etag('/+index/%d' % current_app.storage.repo_revision())
    resp.make_conditional(request)
    return resp

@bp.route('/+sister-index')
def sister_pages():
    """Show index of all pages in a format suitable for SisterPages."""

    text = [
        '%s%s %s\n' % (request.base_url, current_app.get_url(title), title)
        for title in current_app.storage.all_pages()
    ]
    text.sort()
    resp = response.WikiResponse(text, content_type='text/plain')
    resp.set_etag('/+sister-index/%d' % current_app.storage.repo_revision())
    resp.make_conditional(request)
    return resp

@bp.route('/+orphaned')
def orphaned():
    """Show all pages that don't have backlinks."""

    _ = current_app.gettext

    p = page.get_page(request, '')
    orphaned = [
        title
        for title in current_app.index.orphaned_pages()
        if title in current_app.storage
    ]
    html = p.template('list.html',
                         pages=orphaned,
                         class_='orphaned',
                         message=_('List of pages with no links to them'),
                         special_title=_('Orphaned pages'))
    resp = response.WikiResponse(html, content_type='text/html')
    resp.set_etag('/+orphaned/%d' % current_app.storage.repo_revision())
    resp.make_conditional(request)
    return resp

@bp.route('/+wanted')
def wanted():
    """Show all pages that don't exist yet, but are linked."""

    def _wanted_pages_list():
        for refs, title in current_app.index.wanted_pages():
            if not (parser.external_link(title) or title.startswith('+')
                    or title.startswith(':')):
                yield refs, title


    p = page.get_page(request, '')
    html = p.template('wanted.html', pages=_wanted_pages_list())
    resp = response.WikiResponse(html, content_type='text/html')
    resp.set_etag('/+wanted/%d' % current_app.storage.repo_revision())
    resp.make_conditional(request)
    return resp

@bp.route('/+search', methods=['GET', 'POST'])
def search():
    """Serve the search results page."""

    _ = current_app.gettext

    def highlight_html(m):
        return werkzeug.html.b(m.group(0), class_="highlight")

    def search_snippet(title, words):
        """Extract a snippet of text for search results."""

        try:
            text = current_app.storage.page_text(title)
        except error.NotFoundErr:
            return ''
        regexp = re.compile("|".join(re.escape(w) for w in words),
                            re.U | re.I)
        match = regexp.search(text)
        if match is None:
            return ""
        position = match.start()
        min_pos = max(position - 60, 0)
        max_pos = min(position + 60, len(text))
        snippet = werkzeug.escape(text[min_pos:max_pos])
        html = regexp.sub(highlight_html, snippet)
        return html

    def page_search(words, page, request):
        """Display the search results."""

        h = werkzeug.html
        current_app.index.update(current_app)
        result = sorted(current_app.index.find(words), key=lambda x: -x[0])
        yield werkzeug.html.p(h(_('%d page(s) containing all words:')
                              % len(result)))
        yield '<ol id="hatta-search-results">'
        for number, (score, title) in enumerate(result):
            yield h.li(h.b(page.wiki_link(title)), ' ', h.i(str(score)),
                       h.div(search_snippet(title, words),
                             class_="hatta-snippet"),
                       id_="search-%d" % (number + 1))
        yield '</ol>'

    query = request.values.get('q', '').strip()

    p = page.get_page(request, '')
    if not query:
        url = current_app.get_url(view='all_pages', external=True)
        return response.redirect(url, code=303)
    words = tuple(current_app.index.split_text(query))
    if not words:
        words = (query,)
    title = _('Searching for "%s"') % " ".join(words)
    content = page_search(words, p, request)
    html = p.template('page_special.html', content=content,
                         special_title=title)
    return response.WikiResponse(html, content_type='text/html')

@bp.route('/+search/<title:title>', methods=['GET', 'POST'])
def backlinks(title):
    """Serve the page with backlinks."""


    current_app.index.update(current_app)
    p = page.get_page(request, title)
    html = p.template('backlinks.html',
                         pages=current_app.index.page_backlinks(title))
    resp = response.WikiResponse(html, content_type='text/html')
    resp.set_etag('/+search/%d' % current_app.storage.repo_revision())
    resp.make_conditional(request)
    return resp

@bp.route('/+download/scripts.js')
def scripts_js():
    """Server the default scripts"""

    return _serve_default(request, 'scripts.js',
                               mime='text/javascript')

@bp.route('/+download/style.css')
def style_css():
    """Serve the default style"""

    return _serve_default(request, 'style.css',
                               mime='text/css')

@bp.route('/+download/pygments.css')
def pygments_css():
    """Serve the default pygments style"""

    _ = current_app.gettext
    if pygments is None:
        raise error.NotImplementedErr(
            _("Code highlighting is not available."))

    pygments_style = current_app.pygments_style
    if pygments_style not in pygments.styles.STYLE_MAP:
        pygments_style = 'default'
    formatter = pygments.formatters.HtmlFormatter(style=pygments_style)
    style_defs = formatter.get_style_defs('.highlight')
    return _serve_default(request, 'pygments.css', style_defs,
                               'text/css')

@bp.route('/favicon.ico')
def favicon_ico():
    """Serve the default favicon."""

    return _serve_default(request, 'favicon.ico',
                               mime='image/x-icon')

@bp.route('/robots.txt')
def robots_txt():
    """Serve the robots directives."""

    return _serve_default(request, 'robots.txt',
                               mime='text/plain')


@bp.route('/+edit/<title:title>', methods=['GET'])
def edit(title, preview=None, captcha_error=None):
    page.check_lock(current_app, title)

    exists = title in current_app.storage

    p = page.get_page(request, title, wiki=current_app)
    html = p.render_editor(preview, captcha_error)
    if not exists:
        resp = response.WikiResponse(html, content_type="text/html",
                                 status=404)

    elif preview:
        resp = response.WikiResponse(html, content_type="text/html")
    else:
        resp = response.response(request, title, html, '/edit')
    resp.headers['Cache-Control'] = 'no-cache'
    return resp

@bp.route('/+edit/<title:title>', methods=['POST'])
def save(title):
    _ = current_app.gettext

    page.check_lock(current_app, title)
    url = current_app.get_url(title)
    if request.form.get('cancel'):
        if title not in current_app.storage:
            url = current_app.get_url(current_app.front_page)
    if request.form.get('preview'):
        text = request.form.get("text")
        if text is not None:
            lines = text.split('\n')
        else:
            lines = [werkzeug.html.p(werkzeug.html(
                _('No preview for binaries.')))]
        return edit(title, preview=lines)
    elif request.form.get('save'):
        if captcha and current_app.recaptcha_private_key:
            resp = captcha.submit(
                request.form.get('recaptcha_challenge_field', ''),
                request.form.get('recaptcha_response_field', ''),
                current_app.recaptcha_private_key, request.remote_addr)
            if not resp.is_valid:
                text = request.form.get("text", '')
                return edit(request, title, preview=text.split('\n'),
                                 captcha_error=response.error_code)
        comment = request.form.get("comment", "")
        if 'href="' in comment or 'http:' in comment:
            raise error.ForbiddenErr()
        author = request.get_author()
        text = request.form.get("text")
        try:
            parent = int(request.form.get("parent"))
        except (ValueError, TypeError):
            parent = None
        p = page.get_page(request, title)
        if text is not None:
            if title == current_app.locked_page:
                for link, label in p.extract_links(text):
                    if title == link:
                        raise error.ForbiddenErr(
                            _("This page is locked."))
            if text.strip() == '':
                current_app.storage.delete_page(title, author, comment)
                url = current_app.get_url(current_app.front_page)
            else:
                current_app.storage.save_text(title, text, author, comment,
                                       parent)
        else:
            text = ''
            upload = request.files.get('data')
            if upload and upload.stream and upload.filename:
                f = upload.stream
                current_app.storage.save_data(title, f.read(), author,
                                       comment, parent)
            else:
                current_app.storage.delete_page(title, author, comment)
                url = current_app.get_url(current_app.front_page)
        current_app.index.update(current_app)
    resp = response.redirect(url, code=303)
    resp.set_cookie('author',
                        werkzeug.url_quote(request.get_author()),
                        max_age=604800)
    return resp


@bp.route('/+download/<title:title>')
def download(title):
    """Serve the raw content of a page directly from disk."""


    mime = page.page_mime(title)
    if mime == 'text/x-wiki':
        mime = 'text/plain'
    data = current_app.storage.page_data(title)
    resp = response.response(request, title, data,
                             '/download', mime, size=len(data))
    resp.direct_passthrough = True
    return resp

@bp.route('/<title:title>')
@bp.route('/')
def view(title=None):
    _ = current_app.gettext

    if title is None:
        title = current_app.front_page
    p = page.get_page(request, title)
    try:
        content = p.view_content()
    except error.NotFoundErr:
        if current_app.fallback_url:
            url = current_app.fallback_url
            if '%s' in url:
                url = url % werkzeug.url_quote(title)
            else:
                url = "%s/%s" % (url, werkzeug.url_quote(title))
            return response.redirect(url, code=303)
        if current_app.read_only:
            raise error.NotFoundErr(_("Page not found."))

        url = current_app.get_url(title, 'edit', external=True)
        return response.redirect(url, code=303)
    html = p.template("page.html", content=content)
    dependencies = p.dependencies()
    etag = '/(%s)' % ','.join(dependencies)
    return response.response(request, title, html, etag=etag)

