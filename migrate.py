
import os
import re
import sqlite3
import dateutil
from models import Database, Page, CalendarHelper


importer_user_id = 1


def migrate_from_dokuwiki(page_path, calendar_db_path):
    db = Database()
    db.connect('db/pine.sqlite3')
    import_dokuwiki_pages(db, page_path)
    import_dokuwiki_calendar(db, calendar_db_path)

def import_dokuwiki_pages(db, page_path):
    for dirpath, dirs, files in os.walk(page_path):
        for filename in files:
            pagename = extract_pagename(page_path, dirpath, filename)
            if pagename:
                import_page(db, '/'.join([dirpath, filename]), pagename)

def extract_pagename(page_path, dirpath, filename):
    dirpath2 = dirpath[len(page_path):]
    if not filename.endswith('.txt'):
        return None
    filename2 = filename[0:-4]
    dirpath3 = dirpath2.replace('/', ':')
    if dirpath3 == '':
        return filename2
    else:
        return ':'.join([dirpath3, filename2])
    
def import_page(db, fs_path, pagename):
    print('import_page', fs_path, pagename)
    file = open(fs_path, 'r')
    content = file.read()
    file.close()
    page = Page(pagename, content)
    page.last_modified_by_user_id = 1
    db.update_page(page)
    db.db.commit()
    
def import_dokuwiki_calendar(db, calendar_db_path):
    calendar_db = sqlite3.connect(calendar_db_path)
    for row in calendar_db.execute('''select calendardata from calendarobjects'''):
        event_text, timestamp = parse_calendarobject(row[0])
        if event_text and timestamp:
            import_calendar_item(db, event_text, timestamp)

def parse_calendarobject(content):
    re1 = re.compile(r'SUMMARY:(.+)')
    re2 = re.compile(r'DTSTAMP:(.+)')
    event_text = None
    timestamp = None
    for line in content.split('\n'):
        match = re1.match(line)
        if match:
            (s,) = match.groups(1)
            event_text = s.strip()
        match = re2.match(line)
        if match:
            (s,) = match.groups(1)
            timestamp = dateutil.parser.parse(s.strip())
    return (event_text, timestamp)

def import_calendar_item(db, event_text, timestamp):
    event_text = event_text.replace('\\', '')
    helper = CalendarHelper(timestamp.month, timestamp.year)
    pagename = helper.pagename_for_day(timestamp.day)
    page = Page(pagename, event_text)
    page.last_modified_by_user_id = importer_user_id
    print('import calendar item: {}'.format(event_text))
    db.update_page(page)
    db.db.commit()

def go():
    migrate_from_dokuwiki(
        '/home/ajb/dokuwiki_import/',
        '/home/ajb/davcal.sqlite3')
    
    
