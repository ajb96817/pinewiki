

import math
import json
import hashlib
import sqlite3
import redis
import os
import sys
import uuid
import calendar
import time
import datetime
import dateutil.tz
import dateutil.parser
from flask_login import UserMixin
import flask
from flask import url_for, g
import werkzeug.utils
import markdown
import xml.etree.ElementTree
import re

from site_config import site_config



# DokuWiki syntax:
#   [[pagename]], [[path1:path2:pagename]], [[pagename|Link Text]]
class WikiLinkExtension(markdown.extensions.Extension):
    def extendMarkdown(self, md):
        self.md = md
        processor = WikiLinkInlineProcessor(r'\[\[([^]]+)\]\]')
        processor.md = md
        processor.all_pagenames_set = self.all_pagenames_set
        md.inlinePatterns.register(processor, 'wikilink', 75)
        processor2 = WikiFileInlineProcessor(r'\{\{([^}]+)\}\}')
        md.inlinePatterns.register(processor2, 'wikilfile', 76)
        processor3 = ImplicitURIInlineProcessor(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        md.inlinePatterns.register(processor3, 'implicituri', 77)
        md.parser.blockprocessors.register(DokuwikiHeaderBlockProcessor(md.parser), 'dokuwikiheader', 175)
        md.parser.blockprocessors.register(EncryptionBlockProcessor(md.parser), 'encryption', 160)

class ImplicitURIInlineProcessor(markdown.inlinepatterns.InlineProcessor):
    def handleMatch(self, m, data):
        uri = m.group()
        a = xml.etree.ElementTree.Element('a')
        a.text = uri
        a.set('href', uri)
        a.set('class', 'implicit_uri')
        return a, m.start(0), m.end(0)
        

class WikiLinkInlineProcessor(markdown.inlinepatterns.InlineProcessor):
    def handleMatch(self, m, data):
        if m.group(1).strip():
            pagename = m.group(1).strip()
            # recognize [[pagename|linktext]]
            pieces = pagename.split('|')
            if len(pieces) == 2:
                pagename, linktext = [p.strip() for p in pieces]
            else:
                linktext = pagename
            # TODO: if pagename is a full URI handle that appropriately
            pagename = self.convert_pagename(pagename)
            url = '/' + pagename
            a = xml.etree.ElementTree.Element('a')
            a.text = linktext
            a.set('href', url)
            if pagename in self.all_pagenames_set:
                a.set('class', 'wikilink')
            else:
                a.set('class', 'wikilink_missing')
        else:
            a = ''
        return a, m.start(0), m.end(0)

    # "My Pagename" -> "my_pagename" etc.
    def convert_pagename(self, pagename):
        return pagename.strip().lower().replace(' ', '_')
    

class WikiFileInlineProcessor(markdown.inlinepatterns.InlineProcessor):
    def handleMatch(self, m, data):
        if m.group(1).strip():
            path = m.group(1).strip()
            # recognize {{filename|linktext}}
            pieces = path.split('|')
            if len(pieces) == 2:
                path, linktext = [p.strip() for p in pieces]
            else:
                linktext = path
            path_components = path.split('/')
            filename = path_components[-1]
            path_prefix = '/'.join(path_components[0:-1])
            url = '/download_file/{}?path={}'.format(filename, path_prefix)
            a = xml.etree.ElementTree.Element('a')
            a.text = linktext
            a.set('href', url)
        else:
            a = ''
        return a, m.start(0), m.end(0)

class DokuwikiHeaderBlockProcessor(markdown.blockprocessors.BlockProcessor):
    REGEX = re.compile(r'^(?P<level>=+)(?P<header>[^=]+)=+')
    
    def test(self, parent, block):
        return bool(self.REGEX.search(block))

    def run(self, parent, blocks):
        block = blocks.pop(0)
        m = self.REGEX.search(block)
        if m:
            before = block[:m.start()]
            after = block[m.end():]
            if before:
                # As the header was not the first line of the block and the
                # lines before the header must be parsed first,
                # recursively parse this lines as a block.
                self.parser.parseBlocks(parent, [before])
            # Create header using named groups from RE
            dashcount = len(m.group('level'))
            headerlevel = min(max(7-dashcount, 1), 6)
            h = xml.etree.ElementTree.SubElement(parent, 'h{}'.format(headerlevel))
            h.text = m.group('header').strip()
            if after:
                # Insert remaining lines as first block for future parsing.
                blocks.insert(0, after)

class EncryptionBlockProcessor(markdown.blockprocessors.BlockProcessor):
    START_REGEX = re.compile(r'^<ENCRYPTED>')
    END_REGEX = re.compile(r'</ENCRYPTED>')
    CHUNK_SERIAL_NUMBER = 1

    def test(self, parent, block):
        return re.match(self.START_REGEX, block)

    # Based on BoxBlockProcessor in Python-Markdown extension API docs.
    def run(self, parent, blocks):
        original_block = blocks[0]
        blocks[0] = re.sub(self.START_REGEX, '', blocks[0])
        for block_num, block in enumerate(blocks):
            if re.search(self.END_REGEX, block):
                blocks[block_num] = re.sub(self.END_REGEX, '', block)
                chunk_id = 'encrypted_chunk_{}'.format(self.CHUNK_SERIAL_NUMBER)
                self.CHUNK_SERIAL_NUMBER += 1
                chunk = xml.etree.ElementTree.SubElement(parent, 'div')
                chunk.set('class', 'encrypted_chunk')
                commands = xml.etree.ElementTree.SubElement(chunk, 'div')
                commands.set('class', 'encryption_commands')
                commands.text = '🔒 Encrypted text block - '
                decrypt_command = xml.etree.ElementTree.SubElement(commands, 'a')
                decrypt_command.set('href', '#')
                decrypt_command.set('onclick', "toggleCryptDiv('{}')".format(chunk_id))
                decrypt_command.text = 'Decrypt'
                ciphertext = xml.etree.ElementTree.SubElement(chunk, 'div')
                ciphertext.set('id', chunk_id)
                ciphertext.set('class', 'ciphertext')
                ciphertext.text = ''.join(blocks[0:block_num+1])
                #self.parser.parseBlocks(ciphertext, blocks[0:block_num + 1])
                # remove used blocks
                for i in range(0, block_num + 1):
                    blocks.pop(0)
                return True  # or could have had no return statement
            # No closing marker!  Restore and do nothing
            blocks[0] = original_block
            return False  # equivalent to our test() routine returning False


class User(UserMixin):
    NOTIFICATION_OPTIONS = [
        ('off', 'No notifications'),
        ('any', 'Notify for any changes'),
        ('chat', 'Notify for chat messages only'),
        ('page', 'Notify for page changes only')
    ]

    def __init__(self, user_id, username):
        self.user_id = user_id
        self.username = username

    def get_id(self):
        return self.user_id

    def set_profile_json(self, profile_json):
        if profile_json is None:
            self.profile = User.default_profile()
        else:
            self.profile = json.loads(profile_json)

    def chat_tint_color(self):
        color = self.profile['chat_color']
        if color and color in ChatroomHelper.COLORS:
            return ChatroomHelper.COLOR_TINTS[ChatroomHelper.COLORS.index(color)]
        else:
            return '#fff'

    def email_throttle_minutes_left(self):
        profile = self.profile
        if profile.get('email_throttle_enabled', False):
            last_sent_timestamp = profile.get('email_last_sent_timestamp', None)
            if last_sent_timestamp is None: return 0
            elapsed_seconds = time.time() - last_sent_timestamp
            throttle_minutes = profile.get('email_throttle_minutes', 0)
            return max(0, math.ceil(throttle_minutes - elapsed_seconds/60))
        else:
            return 0
        
    def disarm_email_throttle(self):
        self.profile['email_last_sent_timestamp'] = None
        g.database.save_user_changes(self)

    # Send an email notification, unconditionally.
    # This adds the email task to a Redis job queue.
    def send_email_notification(self, notification_type, message):
        profile = self.profile
        app = flask.current_app
        subject = 'pinewiki: {} notification'.format(notification_type)
        recipients = [line.strip() for line in profile.get('email_recipients', '').splitlines() if '@' in line]
        task = {
            'smtp_hostname': profile.get('smtp_hostname', ''),
            'smtp_port': profile.get('smtp_port', 25),
            'use_tls': profile.get('smtp_use_tls', False),
            'use_ssl': profile.get('smtp_use_ssl', False),
            'username': profile.get('smtp_username', ''),
            'password': profile.get('smtp_password', ''),
            'subject': subject,
            'sender': profile.get('smtp_default_sender', ''),
            'recipients': recipients,
            'body': message
        }
        task_json = json.dumps(task)
        r = redis.Redis(host=site_config.redis['host'], port=site_config.redis['port'])
        r.rpush('email_task_queue', task_json)
        r.close()
        # update last-sent timestamp to implement rate throttling
        self.profile['email_last_sent_timestamp'] = time.time()
        g.database.save_user_changes(self)

    def perform_check_in(self):
        self.profile['check_in_timestamp'] = time.time()
        g.database.save_user_changes(self)

    @classmethod
    def default_profile(cls):
        return {
            'chat_color': ChatroomHelper.COLORS[0],
            'notifications': 'any',
            'status': 'idle',
            'status_message': '',
            'email_notifications': 'off',
            'email_throttle_enabled': False,
            'email_throttle_minutes': 0,
            'email_last_sent_timestamp': None
        }        

    @classmethod
    def fetch_by_id(cls, user_id):
        return g.database.fetch_user_by_id(user_id)

    @classmethod
    def authenticate(cls, username, password):
        return g.database.authenticate_user(username, password)


class Event:
    def formatted_description(self):
        if self.event_type in ['create_page', 'edit_page', 'delete_page']:
            return self._formatted_page_event_description()
        elif self.event_type in ['rename_page']:
            return self._formatted_page_rename_event_description()
        elif self.event_type in ['add_comment', 'delete_comment']:
            return self._formatted_comment_event_description()
        elif self.event_type in ['create_file', 'delete_file', 'move_file']:
            return self._formatted_file_event_description()
        elif self.event_type in ['create_folder', 'delete_folder']:
            return self._formatted_folder_event_description()
        else:
            return '???'

    def _formatted_page_event_description(self):
        if self.event_type == 'create_page':
            action = 'created'
        elif self.event_type == 'edit_page':
            action = 'edited'
        else:
            action = 'deleted'
        return '<strong><a href="{}">{}</a></strong> {} by <strong>{}</strong>'.format(
            url_for('view_page', pagename=self.event_target),
            self.event_target,
            action, self.username)

    def _formatted_page_rename_event_description(self):
        return '<strong><a href="{}">{}</a></strong> renamed to <strong><a href="{}">{}</a></strong> by <strong>{}</strong>'.format(
            url_for('view_page', pagename=self.event_target),
            self.event_target,
            url_for('view_page', pagename=self.event_target_2),
            self.event_target_2,
            self.username)

    def _formatted_comment_event_description(self):
        if self.event_type == 'delete_comment':
            action = 'had a comment deleted'
        else:
            action = 'commented on'
        return '<strong><a href="{}">{}</a></strong> {} by <strong>{}</strong>'.format(
            url_for('view_page', pagename=self.event_target),
            self.event_target,
            action, self.username)

    def _formatted_file_event_description(self):
        new_path = '/'.join(self.event_target_2.split('/')[:-1])
        if self.event_type == 'move_file':
            return '<strong>{}</strong> moved to <strong><a href="{}">{}</a></strong> by <strong>{}</strong>'.format(
                self.event_target,
                url_for('view_directory', path=new_path),
                self.event_target_2,
                self.username)
        if self.event_type == 'create_file':
            action = 'uploaded'
        else:
            action = 'deleted'
        return '<strong><a href="{}">{}/{}</a></strong> {} by <strong>{}</strong>'.format(
            url_for('view_directory', path=self.event_target_2),
            self.event_target_2,
            self.event_target,
            action,
            self.username)

    def _formatted_folder_event_description(self):
        if self.event_type == 'create_folder':
            action = 'created'
        else:
            action = 'deleted'
        return '<strong>{}</strong> folder {} by <strong>{}</strong>'.format(
            self.event_target, action, self.username)

    def is_diffable(self):
        return self.event_type in ['create_page', 'edit_page', 'delete_page']
    
    def formatted_timestamp(self):
        return g.database.convert_timestamp_from_db(self.timestamp)

    def formatted_bytes_changed(self):
        if self.bytes_changed is None:
            return ''
        coefficient = self.bytes_changed
        suffix = 'b'
        if abs(self.bytes_changed) >= 10000:
            coefficient = (self.bytes_changed+1023)//1024
            suffix = 'K'
        if coefficient == 0:
            prefix = '&#177;0'
        elif coefficient < 0:
            prefix = str(coefficient)
        else:
            prefix = '+' + str(coefficient)
        return ' '.join([prefix, suffix])

    def bytes_changed_css_class(self):
        b = self.bytes_changed
        if b is None:
            return 'byteschanged'
        elif b == 0:
            return 'byteschanged byteschanged_zero'
        elif b < 0:
            return 'byteschanged byteschanged_negative'
        else:
            return 'byteschanged byteschanged_positive'


# notification_type: 'chat', 'journal', 'page', 'file', etc.  This is the notification that is being created.
# notification_type_preference: one of User.NOTIFICATION_OPTIONS.  This is the user's selected preference.
def is_notification_type_compatible(notification_type, notification_type_preference):
    if notification_type_preference == 'off':
        return False
    elif notification_type_preference == 'any':
        return True
    elif notification_type_preference == 'chat':
        return notification_type == 'chat'
    elif notification_type_preference == 'page':
        return notification_type != 'chat'
    else:
        return False


def send_email_notificiations(notification_type, message, user_id):
    all_users = g.database.fetch_all_users()
    for user in all_users:
        notification_pref = user.profile.get('email_notifications', 'off')
        if user.user_id != user_id and is_notification_type_compatible(notification_type, notification_pref):
            # Check throttle timeout
            throttle_enabled = user.profile.get('email_throttle_enabled', False)
            last_sent_timestamp = user.profile.get('email_last_sent_timestamp', None)
            throttle_minutes = user.profile.get('email_throttle_minutes', 0)
            if not throttle_enabled or last_sent_timestamp is None or time.time() - last_sent_timestamp >= 60.0*throttle_minutes:
                user.send_email_notification(notification_type, message)


class SiteHelper:
    def sitename(self):
        return site_config.sitename

    def logo_html(self):
        return site_config.logo_html

    def extra_css_url(self):
        if site_config.extra_css:
            return url_for('static', filename=site_config.extra_css)
        else:
            return None
    
    # Generate the top navigation toolbar.
    # Only "features" that are enabled in the site_config will be shown.
    def generate_toolbar(self, toolbar_selection):
        item_specs = [
            ['start', 'Start', 'p', url_for('view_page', pagename='start')],
            ['chat', 'Chat', 't', url_for('view_page', pagename='chat')],
            ['check_in', 'Check In', 'k', url_for('view_check_in')],
            ['calendar', 'Calendar', 'c', url_for('todays_calendar')],
            ['journal', 'Journal', 'j', url_for('view_current_user_journal')],
            ['files', 'Files', 'f', url_for('view_directory', path='')],
            ['recent_changes', 'Recent&nbsp;Changes', 'r', url_for('recent_changes')],
            ['sitemap', 'Sitemap', 'm', url_for('view_sitemap')]]
        item_pieces = [
            self._toolbar_item(*item_spec, toolbar_selection)
            for item_spec in item_specs
            if site_config.feature_enabled(item_spec[0])]
        return ' &ndash; '.join(item_pieces)

    def _toolbar_item(self, item_name, label, accesskey, url, toolbar_selection):
        attributes = [f'href="{url}"']
        if accesskey:
            attributes.append(f'accesskey="{accesskey}"')
        if item_name == toolbar_selection:
            attributes.append('class="current"');
        return ''.join([
            '<a ', ' '.join(attributes), '>',
            label,
            '</a>'])


class CalendarHelper(calendar.Calendar):
    def __init__(self, month, year):
        super().__init__(6)
        self.month = month
        self.year = year

    def breadcrumbs(self):
        return [('start', 'start', False), ('calendar', 'calendar', True)]

    def prev_and_next_month_and_year(self):
        ym = self.year*12 + (self.month-1)
        return (
            (((ym-1)%12)+1, (ym-1)//12),
            (((ym+1)%12)+1, (ym+1)//12))

    def formatted_monthname(self, month, year):
        return '{} {}'.format(calendar.month_name[month], year)

    def day_abbr(self, day):
        return calendar.day_abbr[day]

    def pagename_for_day(self, day):
        return 'calendar:{:02d}_{}_{:04d}'.format(
            day, calendar.month_name[self.month].lower(), self.year)

    PAGENAME_REGEX = re.compile(r'calendar:(?P<day>\d+)_(?P<monthname>\w+)_(?P<year>\d+)$')

    @classmethod
    def parse_calendar_pagename(self, pagename):
        match = self.PAGENAME_REGEX.match(pagename)
        if match:
            return '{} {}, {}'.format(
                match.group('monthname').capitalize(),
                int(match.group('day')),
                match.group('year'))
        else:
            return None

    def load_pages_in_range(self):
        self.page_table = {}
        pages = g.database.fetch_calendar_pages_in_month(self.month, self.year)
        for page in pages:
            self.page_table[page.name] = page

    def load_all_pagenames_set(self):
        self.pagenames_set = g.database.fetch_all_pagenames_set()

    def page_for_day(self, day):
        pagename = self.pagename_for_day(day)
        return self.page_table.get(pagename, None)


class Page:
    def __init__(self, name, content='', title=None):
        self.name = name
        self.content = content
        self.title = title
        self.comments = []

    # TODO: move to a method of Database
    def comments_as_json_string(self):
        if self.comments:
            return json.dumps(
                [comment.as_json() for comment in self.comments])
        else:
            return None

    def comment_with_id(self, comment_id):
        return next(
            (comment for comment in self.comments
             if comment.comment_id == comment_id), None)

    def has_encryption(self):
        return '<ENCRYPTED' in self.content
                       
    def is_empty(self):
        return self.content.strip() == ''

    def content_byte_size(self):
        return (len(self.content) +
                sum(len(comment.content) for comment in self.comments))

    # Remove content and comments.  If the page is then "saved" to the database with
    # database.update_page(), it will be deleted.
    def clear(self):
        self.content = ''
        self.comments = []

    def journal_page_info(self):
        return JournalHelper.parse_journal_pagename(self.name)

    def is_journal_page(self):
        return self.journal_page_info() != None

    # URL for the monthly journal containing this page
    # (self.is_journal_page() has to be true).
    # If expanded_entry_pagename is given, the journal screen will show the
    # given journal page initially expanded (note that the first page is
    # always shown initially expanded regardless).
    def journal_page_url(self, expanded_entry_pagename=None):
        page_info = self.journal_page_info()
        return url_for(
            'view_journal',
            username=page_info['username'],
            year=page_info['year'],
            month=page_info['month_index'],
            expand=expanded_entry_pagename)

    # Returns a list of (parent_page_name, label, is_last)
    def breadcrumbs(self):
        breadcrumbs = []
        if self.name == 'start':  # special case
            pieces = [self.name]
            path = self.name
        else:
            pieces = ['start'] + self.name.split(':')
            path = pieces[1]
        for i, piece in enumerate(pieces):
            if i > 1:
                path = path + ':' + pieces[i]
            breadcrumbs.append(
                ((i == 0 and 'start' or path),
                 piece,
                 i == len(pieces)-1))
        return breadcrumbs
            
    def content_as_markdown(self, newlines_to_breaks=False):
        pagenames_set = g.database.fetch_all_pagenames_set()
        return self.content_as_markdown_with_pagenames_set(
            pagenames_set,
            newlines_to_breaks=newlines_to_breaks)

    def content_as_markdown_with_pagenames_set(self, pagenames_set, newlines_to_breaks=False):
        wikilink_extension = WikiLinkExtension()
        wikilink_extension.all_pagenames_set = pagenames_set
        extensions = ['fenced_code', 'codehilite', wikilink_extension, 'tables']
        if newlines_to_breaks:
            extensions.append('nl2br')
        return markdown.markdown(
            self.content,
            extensions=extensions,
            extension_configs={
                'codehilite': {
                    'linenums': True
                }
            })

    def last_modified_by_username(self):
        user = User.fetch_by_id(self.last_modified_by_user_id)
        if user:
            return user.username
        else:
            return '[deleted]'

    def formatted_last_modified_timestamp(self):
        return g.database.convert_timestamp_from_db(self.last_modified_timestamp)

    def formatted_last_modified_date(self):
        date = self.last_modified_date()
        return date.strftime('%A %B %-d, %Y')

    def last_modified_date(self):
        return g.database.db_timestamp_to_date(self.last_modified_timestamp)

    def add_comment(self, author_user, content):
        comment_id = str(uuid.uuid4()).replace('-', '')
        timestamp_string = str(time.time())
        comment = PageComment(
            self, comment_id, author_user.username,
            timestamp_string, content)
        self.comments.append(comment)
        g.database.update_page(self, 'add_comment')
        g.database.create_page_add_comment_notification(self, author_user)
        return comment

    def delete_comment(self, comment, deleting_user):
        if comment in self.comments:
            self.comments.remove(comment)
            g.database.update_page(self, 'delete_comment')
            g.database.create_page_delete_comment_notification(self, deleting_user)
            return True
        else:
            return False

        
# TODO: timestamp code is duplicated in ChatroomHelper
class PageComment:
    @staticmethod
    def from_json(json, page):
        return PageComment(
            page,
            json['comment_id'], json['author_username'],
            json['timestamp_string'], json['content'])
    
    def __init__(self, page, comment_id, author_username, timestamp_string, content):
        self.page = page  # NOTE: creates cyclic reference, should try to fix
        self.comment_id = comment_id  # UUID string, without dashes
        self.author_username = author_username
        self.timestamp_string = timestamp_string
        self.content = content

    def as_json(self):
        return {
            'comment_id': self.comment_id,
            'author_username': self.author_username,
            'timestamp_string': self.timestamp_string,
            'content': self.content
        }

    # Comments are considered editable/deletable by a user if they were authored
    # by that user, or else are attached to a journal page owned by that user.
    def is_editable_by_user(self, user):
        if self.author_username == user.username:
            return True
        journal_page_info = self.page.journal_page_info()
        if journal_page_info != None:
            return journal_page_info['username'] == user.username
        return False

    def formatted_timestamp(self):
        t = float(self.timestamp_string)
        dt_utc = datetime.datetime.fromtimestamp(t, tz=dateutil.tz.tzutc())
        dt_local = dt_utc.astimezone(dateutil.tz.tzlocal())
        return dt_local.strftime('%d-%b-%Y %I:%M:%S %p')

    # NOTE: This is a stripped-down version of normal page Markdown rendering.
    # No wikilinks, tables, code formatting, etc.
    def content_as_markdown(self):
        return markdown.markdown(
            self.content,
            extensions=['nl2br'])
            

class FileHelper:
    def __init__(self):
        self.basedir = '/'.join([flask.current_app.root_path, 'files'])

    def breadcrumbs(self):
        return [('start', 'start', False), ('files', 'files', True)]

    PATH_COMPONENT_REGEX = re.compile(r'^[a-zA-Z0-9_]+$')

    def validate_path_component(self, path_component):
        return bool(self.PATH_COMPONENT_REGEX.match(path_component)) and len(path_component) < 100

    FILE_EXTENSION_REGEX = re.compile(r'\.(\w{1,10})')
    
    def file_extension_icon_url(self, filename):
        basename, extension = os.path.splitext(filename)
        match = self.FILE_EXTENSION_REGEX.match(extension)
        if match:
            ext = match.group(1)
            icon_path = '/'.join([flask.current_app.root_path, 'static', 'filetype_icons', ext+'.png'])
            if os.path.exists(icon_path):
                return '/'.join(['', 'static', 'filetype_icons', ext+'.png'])
        return None

    # path:  dir1/dir2/dir3
    def validate_path(self, path):
        if path == '':
            return True # special case
        components = path.split('/')
        if components[0] == '':
            # TODO: revisit this
            components = components[1:]
        return (
            len(components) <= 10 and
            all(map(lambda c: self.validate_path_component(c), components)))

    def parent_path(self, path):
        if self.validate_path(path):
            components = path.split('/')
            if len(components) >= 1:
                return '/'.join(components[:-1])
            else:
                return ''
        else:
            return None

    def host_dir_for_path(self, path):
        if self.validate_path(path):
            return '/'.join([self.basedir, path])
        else:
            return None

    def sanitize_filename(self, filename):
        s = werkzeug.utils.secure_filename(filename)
        if len(s) < 1 or len(s) > 100:
            return None
        else:
            return s

    # special case: if path is an empty string, the top-level directories are returned
    def list_subdirectories_and_file_details(self, path):
        if path == '':
            dirname = self.basedir
        else:
            dirname = self.host_dir_for_path(path)
        if dirname is None:
            return (None, None)
        subdirectories = []
        file_details = []
        for direntry in os.scandir(dirname):
            if direntry.is_dir():
                subdirectories.append(direntry.name)
            elif direntry.is_file():
                stat = direntry.stat()
                modtime_utc = datetime.datetime.fromtimestamp(stat.st_mtime, tz=dateutil.tz.tzutc())
                modtime_local = modtime_utc.astimezone(dateutil.tz.tzlocal())
                details = {
                    'name': direntry.name,
                    'size_kb': '{}k'.format((stat.st_size+1023)//1024,),
                    'modtime': modtime_local.strftime('%d-%b-%Y %I:%M %p')
                }
                file_details.append(details)
        subdirectories.sort()
        file_details.sort(key=lambda d: d['name'])
        return subdirectories, file_details

    # Return a sorted list of all current directories/subdirectories.
    def list_all_directories(self):
        directories = ['/']
        self._list_all_directories(self.basedir, '', directories)
        directories.sort()
        return directories

    def _list_all_directories(self, basedir, prefix, directories):
        for direntry in os.scandir(basedir):
            if direntry.is_dir():
                subdir = '/'.join([prefix, direntry.name])
                directories.append(subdir)
                self._list_all_directories(
                    '/'.join([basedir, direntry.name]),
                    subdir,
                    directories)

    # Returns error message if any
    def save_uploaded_file(self, uploaded_file, path, user_id):
        if not self.validate_path(path):
            return 'invalid path'
        sanitized_filename = self.sanitize_filename(uploaded_file.filename)
        if sanitized_filename is None:
            return 'invalid filename'
        full_path = '/'.join([self.basedir, path, sanitized_filename])
        uploaded_file.save(full_path)
        bytesize = os.stat(full_path).st_size
        g.database.record_event(
            'create_file', user_id=user_id,
            event_target=sanitized_filename, event_target_2=path,
            bytes_changed=bytesize)
        return None

    # Attached file ends up in 'attachments/{subdirectory}/{filename}'.
    # The full assigned pathname is returned if successful.
    # If there is a problem, None is returned.
    # NOTE: This does not generate a 'create_file' event notification.
    def save_attachment(self, uploaded_file, subdirectory):
        sanitized_filename = self.sanitize_filename(uploaded_file.filename)
        if sanitized_filename is None:
            return None
        path = '/'.join(['attachments', subdirectory])
        if not self.validate_path(path):
            return None
        full_path = '/'.join([self.basedir, path])
        os.makedirs(full_path, exist_ok=True)
        # TODO: exception handling, return None on error
        uploaded_file.save('/'.join([full_path, sanitized_filename]))
        return '/'.join([path, sanitized_filename])

    # Returns error message if any
    # TODO: factor this logic with save_uploaded_file etc (use full_path_for_file)
    def delete_file(self, path, filename, user_id):
        if not self.validate_path(path):
            return 'invalid path'
        sanitized_filename = self.sanitize_filename(filename)
        if sanitized_filename is None:
            return 'invalid filename'
        full_path = '/'.join([self.basedir, path, sanitized_filename])
        if not os.path.exists(full_path):
            return 'file does not exist'
        if not os.path.isfile(full_path):
            return 'not a file (may be a directory)'
        # Get the size of the file being deleted so it can be logged into the event table.
        bytesize = os.stat(full_path).st_size
        os.remove(full_path)
        g.database.record_event(
            event_type='delete_file', user_id=user_id,
            event_target=sanitized_filename, event_target_2=path,
            bytes_changed=-bytesize)
        return None

    # Returns error message if any
    def rename_or_move_file(self, original_path, original_filename,
                            new_path, new_filename, user_id):
        if not self.validate_path(original_path):
            return 'invalid original path'
        if not self.validate_path(new_path):
            return 'invalid new path'
        original_sanitized_filename = self.sanitize_filename(original_filename)
        new_sanitized_filename = self.sanitize_filename(new_filename)
        if new_sanitized_filename is None:
            return 'invalid filename'
        original_full_path = '/'.join([self.basedir, original_path, original_sanitized_filename])
        if not os.path.exists(original_full_path):
            return 'file does not exist'
        if not os.path.isfile(original_full_path):
            return 'not a file (may be a directory)'
        new_full_path = '/'.join([self.basedir, new_path, new_sanitized_filename])
        if new_full_path == original_full_path:
            return None  # source and dest are the same
        os.rename(original_full_path, new_full_path)
        g.database.record_event(
            'move_file', user_id=user_id,
            event_target='/'.join([original_path, original_sanitized_filename]),
            event_target_2='/'.join([new_path, new_sanitized_filename]))

    def create_directory(self, base_path, new_directory_name, user_id):
        if base_path == '':
            # TODO: revisit
            new_path = new_directory_name
        else:
            new_path = '/'.join([base_path, new_directory_name])
        if not self.validate_path(new_path):
            return 'Invalid path'
        if base_path == '':
            # TODO: revisit
            full_path = '/'.join([self.basedir, new_directory_name])
        else:
            full_path = '/'.join([self.basedir, base_path, new_directory_name])
        if os.path.exists(full_path):
            return 'Folder already exists'
        os.mkdir(full_path)
        g.database.record_event(
            'create_folder', user_id=user_id,
            event_target=new_path)
        return None

    def delete_directory(self, path, user_id):
        if not self.validate_path(path):
            return 'Invalid path'
        if path == '':
            return "Can't delete root folder"
        subdirectories, file_details = self.list_subdirectories_and_file_details(path)
        if len(subdirectories) > 0 or len(file_details) > 0:
            return 'Folder not empty'
        full_path = '/'.join([self.basedir, path])
        os.rmdir(full_path)
        g.database.record_event(
            'delete_folder', user_id=user_id,
            event_target=path)
        return None

    def full_path_for_file(self, path, filename):
        if not self.validate_path(path):
            return None
        sanitized_filename = self.sanitize_filename(filename)
        if len(sanitized_filename) > 100:
            return None
        full_path = '/'.join([self.basedir, path, sanitized_filename])
        if os.path.exists(full_path) and os.path.isfile(full_path):
            return full_path
        else:
            return None


class ChatroomHelper:
    def breadcrumbs(self):
        return [('start', 'start', False), ('chat', 'chat', True)]
    
    # Convert a chat pagename like chat:123456_454325 and return a formatted
    # timestamp in the local timezone.
    def formatted_time_from_chat_pagename(self, pagename):
        timestamp = int(float(pagename.split(':')[1].replace('_', '.')))
        dt_utc = datetime.datetime.fromtimestamp(timestamp, tz=dateutil.tz.tzutc())
        dt_local = dt_utc.astimezone(dateutil.tz.tzlocal())
        return dt_local.strftime('%d-%b-%Y %I:%M:%S %p')
    
    COLORS = ['#fdd', '#ddf', '#dfd', '#ffd', '#fdf', '#dff']
    COLOR_TINTS = ['#fff8f8', '#f8f8ff', '#f8fff8', '#fffff8', '#fff8ff', '#f8ffff']
    COLORNAMES = ['red', 'blue', 'green', 'yellow', 'pink', 'cyan']
        
    def post_new_chat(self, content, user_id):
        # generate unique pagename
        pagename = 'chat:{}'.format(str(time.time()).replace('.', '_'))
        page = Page(pagename, content)
        page.last_modified_by_user_id = user_id
        g.database.update_page(page)


# journal page name format:
# journal:username:12_nov_2021:04_32pm
class JournalHelper:
    PAGENAME_REGEX = re.compile(
        r'journal:(?P<username>\w+):(?P<day>\d+)_(?P<month_abbr>[a-z]+)_(?P<year>\d+):(?P<hour>\d+)_(?P<minute>\d+)(?P<ampm>[ap]m)$')

    # Build map of lowercase_month_abbr -> month_index
    MONTH_ABBR_MAP = dict()
    for month_index, month_abbr in enumerate(calendar.month_abbr):
        MONTH_ABBR_MAP[month_abbr.lower()] = month_index

    def breadcrumbs(self, user, year, month):
        formatted_date = '{}_{}'.format(calendar.month_abbr[month].lower(), year)
        return [
            ('start', 'start', False),
            ('journal', 'journal', False),
            ('journal/{}'.format(user.username), user.username, False),
            ('journal/{}/{}/{}'.format(user.username, year, month), formatted_date, True)
        ]

    def load_all_pagenames_set(self):
        self.pagenames_set = g.database.fetch_all_pagenames_set()

    @classmethod
    def parse_journal_pagename(self, pagename):
        match = self.PAGENAME_REGEX.match(pagename)
        if match is None:
            return None
        month_abbr = match.group('month_abbr')
        hour = int(match.group('hour')) % 12
        ampm_offset = 0 if match.group('ampm') == 'am' else 12
        month_index = self.MONTH_ABBR_MAP[month_abbr]
        username = match.group('username')
        if month_index == 0:
            return None  # shouldn't happen
        return {
            'username': match.group('username'),
            'year': int(match.group('year')),
            'month_abbr': month_abbr,
            'month_index': month_index,
            'day': int(match.group('day')),
            'hour': hour + ampm_offset,
            'minute': int(match.group('minute'))
        }

    @classmethod
    def pagename_for_username_and_datetime(self, username, dt):
        formatted_dt = dt.strftime('%d_%b_%Y:%I_%M%p').lower()
        return 'journal:{}:{}'.format(username, formatted_dt)

    # Build journal entry summary for the given user and retrieve a paginated list of
    # pagenames starting at the given year/month (up to max_entries).
    # Entries are sorted by descending timestamp (newest first).
    # NOTE: load_all_pagenames_set() must have been called first before using this.
    # Returns a tuple of:
    #   List of dictionaries of the form:
    #     { 'year': 2021, 'month': 10, 'pagenames': [...] }
    #   List of page names starting a the given year/month.
    def build_entry_summary(self, user, page_year, page_month, max_entries):
        # Build map of pagename->parsed_info
        pagename_to_parsed_map = dict()
        # Keep track of year+month date range as pages are scanned
        newest_ym = oldest_ym = None
        for pagename in self.pagenames_set:
            parsed = JournalHelper.parse_journal_pagename(pagename)
            if parsed is None:
                continue  # Not actually a journal page
            if parsed['username'] != user.username:
                continue  # Only interested in entries by the given user_id
            pagename_to_parsed_map[pagename] = parsed
            # Extend year/month bounds as pages are examined
            ym = (parsed['year'], parsed['month_index'])
            if newest_ym is None or ym > newest_ym:
                newest_ym = ym
            if oldest_ym is None or ym < oldest_ym:
                oldest_ym = ym

        # Generate the table of all (year, month) pairs that will be used, in the correct
        # order.  Note that the tuples will still be there even if there's no journal
        # entries on a particular month - all that matters is the beginning and end
        # year/month range.
        summary_items = []  # one for each year/month
        ym_to_item_map = dict()  # maps (year, month) -> entries in the above
        if newest_ym is None:
            today = datetime.date.today()
            newest_ym = oldest_ym = (today.year, today.month)
        for year in range(newest_ym[0], oldest_ym[0]-1, -1):
            for month in range(12, 0, -1):
                ym = (year, month)
                if ym <= newest_ym and ym >= oldest_ym:
                    summary_item = {
                        'year': year, 'month_index': month,
                        'month_name': calendar.month_name[month], 'pagenames': []
                    }
                    summary_items.append(summary_item)
                    ym_to_item_map[ym] = summary_item

        # Sort journal pagenames in descending order for further processing.
        def sortkey(item):
            p = item[1]
            return (p['year'], p['month_index'], p['day'], p['hour'], p['minute'])
        sorted_journal_items = sorted(
            pagename_to_parsed_map.items(),
            key=sortkey, reverse=True)

        # Populate all the pagenames into summary_items.
        # TODO: May want to remove this if it's not used.
        for pagename, parsed in sorted_journal_items:
            summary_item = ym_to_item_map[(parsed['year'], parsed['month_index'])]
            summary_item['pagenames'].append(pagename)

        paginated_pagenames = []
        for index, (pagename, parsed) in enumerate(sorted_journal_items):
            if parsed['year'] == page_year and parsed['month_index'] == page_month:
                paginated_pagenames = list(map(lambda i: i[0], sorted_journal_items[index:index+max_entries]))
                break

        return summary_items, paginated_pagenames

    def formatted_time_from_journal_pagename(self, pagename, include_weekday=False):
        parsed = JournalHelper.parse_journal_pagename(pagename)
        hour = (parsed['hour']-1)%12 + 1
        ampm = 'pm' if parsed['hour'] >= 12 else 'am'
        result = '''{:02d}-{}-{:04d} at {}:{:02d}{}'''.format(
            parsed['day'], parsed['month_abbr'].capitalize(), parsed['year'],
            hour, parsed['minute'], ampm)
        if include_weekday:
            weekday = calendar.weekday(parsed['year'], parsed['month_index'], parsed['day'])
            weekday_abbr = calendar.day_abbr[weekday]
            result = '{} {}'.format(weekday_abbr, result)
        return result

    def year_and_month_index_from_journal_pagename(self, pagename):
        parsed = JournalHelper.parse_journal_pagename(pagename)
        return parsed['year'], parsed['month_index']

    # Returns created/updated Page object
    def post_journal_entry(self, content, title, user, timestamp):
        pagename = JournalHelper.pagename_for_username_and_datetime(user.username, timestamp)
        # TODO: merge already-existing pages with new content
        page = Page(pagename, content, title)
        page.last_modified_by_user_id = user.user_id
        g.database.update_page(page)
        return page

class CheckInHelper:
    def breadcrumbs(self):
        return [
            ('start', 'start', False),
            ('check_in', 'check_in', True)]

    def load_check_in_info(self):
        all_users = g.database.fetch_all_users()
        return [self.check_in_info_for_user(user) for user in all_users]

    def check_in_info_for_user(self, user):
        check_in_timestamp = user.profile.get('check_in_timestamp')
        time_ago_string = self.time_ago_string(check_in_timestamp, include_seconds=False)
        return {
            'username': user.username,
            'time_ago_string': time_ago_string
        }

    def time_ago_string(self, timestamp, include_seconds=False):
        if timestamp is None:
            return 'never'
        elapsed_seconds = int(time.time() - timestamp)
        if elapsed_seconds <= 60:
            return 'just now'
        minutes, seconds = divmod(elapsed_seconds, 60)
        hours, minutes = divmod(minutes, 60)
        days, hours = divmod(hours, 24)
        pieces = []
        if days > 0:
            pieces.append('{} day{}'.format(days, '' if days == 1 else 's'))
        if hours > 0:
            pieces.append('{} hour{}'.format(hours, '' if hours == 1 else 's'))
        if minutes > 0:
            pieces.append('{} minute{}'.format(minutes, '' if minutes == 1 else 's'))
        if include_seconds and seconds > 0:
            pieces.append('{} second{}'.format(seconds, '' if seconds == 1 else 's'))
        return ', '.join(pieces) + ' ago'


class Database:
    def connect(self, db_path = None):
        db_path = db_path or '/'.join([flask.current_app.root_path, 'db', 'pine.sqlite3'])
        self.db = sqlite3.connect(db_path)
        self.init_or_upgrade()

    def disconnect(self):
        self.db.close()
        self.db = None

    def init_or_upgrade(self):
        c = self.db.cursor()
        c.execute('create table if not exists schema_info (version integer)')
        self.db.commit()
        v = c.execute('select version from schema_info').fetchone()
        if v == None:
            self.create_initial_schema()

    def create_initial_schema(self):
        c = self.db.cursor()
        c.execute('insert into schema_info (version) values (?)', (1,))
        c.executescript(self._initial_schema_script())
        self.db.commit()
        self.create_user('ajb', 'ajb123')

    def _initial_schema_script(self):
        return (
            '''
            create table user (
                id integer primary key autoincrement,
                username text,
                password_sha1 text,
                profile text);
            create table page (
                name text primary key,
                title text,
                content text,
                comments_json json,
                last_modified_timestamp text,
                last_modified_by_user_id integer);
            create virtual table page_fts using fts5(name, content);
            create table event (
                id integer primary key autoincrement,
                event_type text,
                event_target text,
                event_target_2 text,
                bytes_changed integer,
                content text,
                user_id integer,
                timestamp text);
            create index event_target_type_index on event (event_target, event_type, timestamp);
            create table notification (
                type text,
                message text,
                user_id integer,
                timestamp text);
            create index notification_timestamp_index on notification (timestamp);
            ''')
        
    # Turn UTC timestamp string from the database into a datetime object in the local timezone.
    def db_timestamp_to_datetime(self, s):
        utc_dt = datetime.datetime.strptime(s, '%Y-%m-%d %H:%M:%S')
        utc_dt = utc_dt.replace(tzinfo=dateutil.tz.tzutc())
        return utc_dt.astimezone(dateutil.tz.tzlocal())

    # Turn UTC timestamp string from the database into a formatted time string in the local timezone.
    def convert_timestamp_from_db(self, s):
        local_dt = self.db_timestamp_to_datetime(s)
        return local_dt.strftime('%d-%b-%Y %I:%M:%S %p')

    def db_timestamp_to_date(self, s):
        local_dt = self.db_timestamp_to_datetime(s)
        return datetime.date(local_dt.year, local_dt.month, local_dt.day)

    def hash_password(self, password):
        salted = ':'.join(['pinewikisalt34284324', password])
        h = hashlib.sha256()
        h.update(salted.encode('UTF-8'))
        return h.hexdigest()

    def create_user(self, username, password):
        profile = User.default_profile()
        password_sha1 = self.hash_password(password)
        profile_json = json.dumps(profile)
        c = self.db.cursor()
        c.execute('insert into user (username, password_sha1, profile) values (?, ?, ?)',
                  (username, password_sha1, profile_json))
        user_id = c.lastrowid
        self.db.commit()
        # set "real" chat color (user ID is needed for this)
        user = self.fetch_user_by_id(user_id)
        chat_color = ChatroomHelper.COLORS[(user_id-1) % len(ChatroomHelper.COLORS)]
        user.profile['chat_color'] = chat_color
        self.save_user_changes(user)
        return user

    def delete_user_id(self, user_id):
        self.db.execute('delete from user where id = ?', (user_id,))

    def save_user_changes(self, user):
        profile_json = json.dumps(user.profile)
        self.db.execute('update user set username = ?, profile = ? where id = ?',
                        (user.username, profile_json, user.user_id))

    # Returns True if password updated successfully; False if old_password doesn't match what's there.
    def change_user_password(self, user_id, old_password, new_password):
        old_password_sha1 = self.hash_password(old_password)
        row = self.db.execute('select password_sha1 from user where id = ?', (user_id,)).fetchone()
        if row is None or row[0] != old_password_sha1:
            return False
        new_password_sha1 = self.hash_password(new_password)
        self.db.execute('update user set password_sha1 = ? where id = ?',
                        (new_password_sha1, user_id))
        return True

    def reset_user_password(self, user_id):
        new_password_sha1 = self.hash_password('hello')
        self.db.execute('update user set password_sha1 = ? where id = ?',
                        (new_password_sha1, user_id))

    def fetch_user_by_username(self, username):
        row = self.db.execute('select id, profile from user where username = ?', (username,)).fetchone()
        if row:
            u = User(int(row[0]), username)
            u.set_profile_json(row[1])
            return u
        else:
            return None

    def fetch_user_by_id(self, user_id):
        row = self.db.execute('select username, profile from user where id = ?', (user_id,)).fetchone()
        if row:
            u = User(int(user_id), row[0])
            u.set_profile_json(row[1])
            return u
        else:
            return None

    def fetch_all_users(self):
        all_users = []
        for row in self.db.execute('select id, username, profile from user order by id asc'):
            u = User(int(row[0]), row[1])
            u.set_profile_json(row[2])
            all_users.append(u)
        return all_users

    # Return a dict(user_id=>user) for a collection of user_ids
    def _load_user_id_to_user_map(self, user_ids):
        d = dict()
        if len(user_ids) == 0:
            return d
        in_clause = ','.join(map(str, user_ids))
        for row in self.db.execute('select id, username, profile from user where id in ({})'.format(in_clause,)):
            u = User(int(row[0]), row[1])
            u.set_profile_json(row[2])
            d[row[0]] = u
        return d

    def authenticate_user(self, username, password):
        password_sha1 = self.hash_password(password)
        row = self.db.execute('select id, username, password_sha1, profile from user where username = ?', (username,)).fetchone()
        if row and row[2] == password_sha1:
            u = User(int(row[0]), row[1])
            u.set_profile_json(row[3])
            return u
        else:
            return None

    def record_event(self, event_type, user_id, event_target=None, event_target_2=None, content=None, bytes_changed=None):
        self.db.execute(
            '''insert into event (event_type, event_target, event_target_2, bytes_changed, content, user_id, timestamp)
            values (?, ?, ?, ?, ?, ?, datetime('now'))''',
            (event_type, event_target, event_target_2, bytes_changed, content, user_id))

    def fetch_page(self, pagename):
        pages = self.fetch_pages([pagename])
        if len(pages) == 1:
            return pages[0]
        else:
            return None

    # NOTE: pages will be returned in the same order as in 'pagenames'.
    def fetch_pages(self, pagenames):
        in_clause = ','.join(['"'+p+'"' for p in pagenames])
        pages = [
            self._page_from_db_row(row)
            for row in self.db.execute(
                '''select name, title, content, comments_json,
                last_modified_timestamp, last_modified_by_user_id
                from page where name in ({})'''.format(in_clause,))]
        page_order_map = dict()
        for index, pagename in enumerate(pagenames):
            page_order_map[pagename] = index
        pages.sort(key=lambda p: page_order_map[p.name])
        return pages

    # event_type:
    #   'edit_page' - normal page update/creation/deletion (i.e. page.content changed)
    #   'add_comment', 'delete_comment' - comment was added to or deleted from the page
    def update_page(self, page, event_type='edit_page'):
        old_page = self.fetch_page(page.name)
        if old_page:
            if page.is_empty():
                # Old page is being deleted.
                self.record_event(
                    event_type='delete_page',
                    event_target=page.name,
                    user_id=page.last_modified_by_user_id,
                    content=old_page.content,
                    bytes_changed=-old_page.content_byte_size())
                self.db.execute('delete from page where name = ?', (page.name,))
                self.db.execute('delete from page_fts where name = ?', (page.name,))
            else:
                # Existing page content/title/comments are being changed.
                bytes_changed = page.content_byte_size() - old_page.content_byte_size()
                self.record_event(
                    event_type=event_type,
                    event_target=page.name,
                    user_id=page.last_modified_by_user_id,
                    content=old_page.content,
                    bytes_changed=bytes_changed)
                self.db.execute(
                    '''update page set content = ?, title = ?, comments_json = ?,
                    last_modified_timestamp = datetime('now'), last_modified_by_user_id = ? where name = ?''',
                    (page.content, page.title, page.comments_as_json_string(),
                     page.last_modified_by_user_id, page.name))
                self.db.execute(
                    'update page_fts set content = ? where name = ?',
                    (page.content, page.name))
        else:
            if page.is_empty():
                # 'new' empty page is being 'created' - ignore
                pass
            else:
                # new page is being created
                self.record_event(
                    event_type='create_page',
                    event_target=page.name,
                    user_id=page.last_modified_by_user_id,
                    content=page.content,
                    bytes_changed=page.content_byte_size())
                self.db.execute(
                    '''insert into page (name, content, title, comments_json, last_modified_timestamp, last_modified_by_user_id)
                    values (?, ?, ?, ?, datetime('now'), ?)''',
                    (page.name, page.content, page.title, page.comments_as_json_string(),
                     page.last_modified_by_user_id))
                self.db.execute(
                    'insert or replace into page_fts (name, content) values (?, ?)',
                    (page.name, page.content))

    def rename_page(self, page, new_pagename):
        # Not yet implemented
        pass

    def fulltext_search(self, query, limit=20, offset=0):
        return [
            {'pagename': row[0], 'snippet': row[1]}
            for row in self.db.execute(
                    '''select name, snippet(page_fts, 1, ?, ?, ?, 20)
                    from page_fts where content match ? order by bm25(page_fts) limit ?,?''',
                    ('', '', '...', query, offset, limit))]

    def fetch_all_pagenames_set(self):
        pagenames = set()
        for row in self.db.execute('select name from page'):
            # special case: exclude chat "pages" from this
            if not row[0].startswith('chat:'):
                pagenames.add(row[0])
        return pagenames

    def create_notification(self, notification_type, message, user_id):
        self.db.execute(
            '''insert into notification (type, message, user_id, timestamp)
            values (?, ?, ?, datetime('now'))''',
            (notification_type, message, user_id))
        # prune old notifications
        self.db.execute('''delete from notification where timestamp < datetime('now', '-1 month')''')
        send_email_notificiations(notification_type, message, user_id)

    def create_page_edit_notification(self, page, user):
        pagename = page.name
        if pagename.startswith('chat:'):
            return  # don't notify for chat edits, only for new chat messages
        elif pagename.startswith('calendar:'):
            parsed_date_string = CalendarHelper.parse_calendar_pagename(pagename)
            if parsed_date_string is None:
                message = '{} edited the calendar'.format(user.username)
            else:
                message = '{} edited {} on the calendar'.format(user.username, parsed_date_string)
            self.create_notification('page', message, user.user_id)
        else:
            message = '{} edited {}'.format(user.username, pagename)
        self.create_notification('page', message, user.user_id)

    def create_page_add_comment_notification(self, page, user):
        message = '{} commented on {}'.format(user.username, page.name)
        self.create_notification('add_comment', message, user.user_id)

    def create_page_delete_comment_notification(self, page, user):
        message = '{} deleted a comment on {}'.format(user.username, page.name)
        self.create_notification('delete_comment', message, user.user_id)

    # NOTE: notifications with user_id matching the one provided are ignored.
    def fetch_notifications(self, user_id, cutoff_timestamp=None, limit=10):
        if cutoff_timestamp is None:
            cutoff_timestamp = '0'
        notifications = []
        for row in self.db.execute(
                '''select type, message, user_id, timestamp
                from notification where timestamp > ? and user_id != ? order by timestamp desc limit ?''',
                (cutoff_timestamp, user_id, limit)):
            notifications.append({
                'type': row[0],
                'message': row[1],
                'user_id': row[2],
                'timestamp': row[3]})
        return notifications

    def fetch_sitemap(self):
        page_infos = [
            {'pagename': row[0],
             'filesize': int(row[1]),
             'last_modified_timestamp': self.convert_timestamp_from_db(row[2]),
             'last_modified_by_user_id': int(row[3])}
            for row in self.db.execute(
                    '''select name, length(content), last_modified_timestamp, last_modified_by_user_id
                    from page where name not like ? and name not like ? and name not like ?''',
                    ('chat:%', 'calendar:%', 'journal:%'))]
        page_infos.sort(key=lambda p: p['pagename'])
        user_ids = set(p['last_modified_by_user_id'] for p in page_infos)
        user_id_map = self._load_user_id_to_user_map(user_ids)
        for p in page_infos:
            u = user_id_map.get(p['last_modified_by_user_id'], None)
            p['last_modified_by_username'] = u.username if u else '[deleted]'
            p['indent_level'] = p['pagename'].count(':')
        return page_infos

    # Fetch recent chat pages, up to 'limit'; most recent will be first in the list.
    # Only pages newer than 'limit_in_seconds' seconds old will be fetched.
    def fetch_chat_pages(self, limit=500, limit_in_seconds=48*60*60):
        time_cutoff = time.time() - limit_in_seconds
        pagename_cutoff = 'chat:{}'.format(str(time_cutoff).replace('.', '_'))
        pages = [
            self._page_from_db_row(row)
            for row in self.db.execute(
                    '''select name, title, content, comments_json,
                    last_modified_timestamp, last_modified_by_user_id 
                    from page where name >= ? and name like ? order by name desc limit ?''',
                    (pagename_cutoff, 'chat:%', limit))]
        self._load_usernames_for_pages(pages, include_profiles=True)
        return pages

    # pagename: chat:12934343_432432
    def delete_chat_page(self, pagename):
        is_valid_pagename = bool(re.match(r'^chat:\d+_\d+$', pagename)) and len(pagename) < 100
        if is_valid_pagename:
            self.db.execute('delete from page where name = ?', (pagename,))
            self.db.execute('delete from page_fts where name = ?', (pagename,))

    def fetch_calendar_pages_in_month(self, month, year):
        pattern = 'calendar:%_{}_{:04d}'.format(
            calendar.month_name[month].lower(), year)
        return [
            self._page_from_db_row(row)
            for row in self.db.execute(
                    '''select name, title, content, comments_json,
                    last_modified_timestamp, last_modified_by_user_id
                    from page where name like ?''', (pattern,))]

    def _page_from_db_row(self, row):
        p = Page(row[0], row[2], row[1])
        if row[3]:
            comments_json = json.loads(row[3])
            p.comments = [
                PageComment.from_json(comment_json, p)
                for comment_json in json.loads(row[3])]
        p.last_modified_timestamp = row[4]
        p.last_modified_by_user_id = row[5]
        return p

    def fetch_recent_events(self, limit=20, skip=0):
        events = []
        for row in self.db.execute(
                '''select id, event_type, event_target, event_target_2, bytes_changed, user_id, timestamp
                from event order by timestamp desc limit ?,?''', (skip, limit)):
            event = Event()
            event.id = row[0]
            event.event_type = row[1]
            event.event_target = row[2]
            event.event_target_2 = row[3]
            event.bytes_changed = row[4]
            event.user_id = row[5]
            event.timestamp = row[6]
            events.append(event)
        self._load_usernames_for_events(events)
        return events

    def fetch_page_events(self, pagename, limit=20, skip=0):
        events = []
        for row in self.db.execute(
                '''select id, event_type, event_target, event_target_2, bytes_changed, user_id, timestamp
                from event where event_target = ? and event_type in ('create_page','edit_page','delete_page','rename_page','add_comment','delete_comment')
                order by timestamp desc limit ?,?''',
                (pagename, skip, limit)):
            event = Event()
            event.id = row[0]
            event.event_type = row[1]
            event.event_target = row[2]
            event.event_target_2 = row[3]
            event.bytes_changed = row[4]
            event.user_id = row[5]
            event.timestamp = row[6]
            events.append(event)
        self._load_usernames_for_events(events)
        return events

    # Populate event.username efficiently for a group of events
    def _load_usernames_for_events(self, events):
        user_ids = set(event.user_id for event in events if event.user_id != None)
        user_map = self._load_user_id_to_user_map(user_ids)
        for event in events:
            u = user_map.get(event.user_id, None)
            event.username = u.username if u else '[deleted]'

    # Same as above but for a list of pages (this is only used for chat pages)
    def _load_usernames_for_pages(self, pages, include_profiles=False):
        user_ids = set(page.last_modified_by_user_id for page in pages)
        user_map = self._load_user_id_to_user_map(user_ids)
        for page in pages:
            u = user_map.get(page.last_modified_by_user_id, None)
            page.user = u
            page.username = u.username if u else '[deleted]'
    

    
