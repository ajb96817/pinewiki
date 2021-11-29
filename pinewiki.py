
import datetime
import dateutil.tz
import re
from flask import g, Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import Database, Page, User, CalendarHelper, ChatroomHelper, JournalHelper, FileHelper


app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
app.config['SECRET_KEY'] = 'ueahrucahrou'
app.config['MAX_CONTENT_LENGTH'] = 100*1024*1024  # max uploaded file size


def current_local_timestamp():
    today = datetime.date.today()
    now_utc = datetime.datetime.now(tz=dateutil.tz.tzutc())
    return now_utc.astimezone(dateutil.tz.tzlocal())


@login_manager.user_loader
def load_user(user_id):
    return User.fetch_by_id(user_id)

@app.before_request
def before_request():
    g.database = Database()
    g.database.connect()

@app.teardown_request
def teardown_request(exception):
    if g.database:
        g.database.db.commit()
        g.database.disconnect()
        g.database = None
    

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        user = User.authenticate(request.form['username'], request.form['password'])
        if user:
            login_user(user, remember=True)
            return redirect(url_for('view_page', pagename='start'))
        else:
            error = 'Invalid username or password.'
    return render_template('login.html', error=error)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def front_page():
    return redirect(url_for('view_page', pagename='start'))

#@app.route('/', defaults={'pagename': 'start'})
@app.route('/<pagename>', methods=['GET'])
@login_required
def view_page(pagename):
    page = g.database.fetch_page(pagename) or Page(pagename)
    rendered_markdown = page.content_as_markdown()
    if pagename == 'start':
        toolbar_selection = 'start'
    elif page.is_journal_page():
        toolbar_selection = 'journal'
    else:
        toolbar_selection = None
    return render_template(
        'view_page.html',
        toolbar_selection=toolbar_selection,
        page=page,
        pagename=pagename,
        breadcrumbs=page.breadcrumbs(),
        rendered_markdown=rendered_markdown)

@app.route('/edit/<pagename>', methods=['GET', 'POST'])
@login_required
def edit_page(pagename):
    page = g.database.fetch_page(pagename) or Page(pagename)
    if page.is_journal_page():
        journal_page_timestamp = JournalHelper().formatted_time_from_journal_pagename(page.name)
        is_owned_journal_page = JournalHelper.parse_journal_pagename(page.name)['username'] == current_user.username
    if request.method == 'GET':
        return render_template(
            'edit_page.html',
            page=page,
            pagename=pagename,
            breadcrumbs=page.breadcrumbs(),
            toolbar_selection=('journal' if page.is_journal_page() else None),
            journal_page_timestamp=journal_page_timestamp,
            is_owned_journal_page=is_owned_journal_page)
    elif request.method == 'POST':
        encrypted_content = request.form['encrypted_page_content']
        if len(encrypted_content) > 0:
            content = encrypted_content
        else:
            content = request.form['page_content']
        if len(content.strip()) == 0:
            # If there's only whitespace, the page will be deleted; but always stripping
            # whitespace with strip() would mess up e.g. indented lists at the beginning.
            content = ''
        action = request.form['action']
        page.content = content
        page.last_modified_by_user_id = current_user.user_id
        if action == 'save':
            g.database.update_page(page)
            g.database.create_page_edit_notification(page, current_user)
        elif action == 'preview':
            return render_template(
                'edit_page.html',
                page=page,
                pagename=pagename,
                breadcrumbs=page.breadcrumbs(),
                rendered_preview=page.content_as_markdown())
        if pagename.startswith('chat:'):
            return redirect(url_for('view_chat'))
        elif pagename.startswith('calendar:'):
            # TODO: redirect to view_calendar with the correct month/year instead
            return redirect(url_for('todays_calendar'))
        elif page.is_journal_page():
            return redirect(url_for('view_journal'))
        else:
            return redirect(url_for('view_page', pagename=page.name))
    
@app.route('/changes', methods=['GET'])
@login_required
def recent_changes():
    per_page = 30
    page_str = request.args.get('page') or '1'
    page_number = max(1, min(100, int(page_str)))
    events1 = g.database.fetch_recent_events(limit=per_page+1, skip=(page_number-1)*per_page)
    more_available = len(events1) > per_page
    events = events1[0:per_page]
    return render_template(
        'changes.html',
        pagename='recent changes',
        toolbar_selection='recent_changes',
        breadcrumbs=[('start', 'start', False), ('changes', 'changes', True)],
        page_number=page_number,
        events=events,
        more_available=more_available)

@app.route('/calendar', methods=['GET'])
@login_required
def todays_calendar():
    now_local = current_local_timestamp()
    return redirect(url_for(
        'view_calendar',
        year=now_local.year,
        month='{:02d}'.format(now_local.month)))

@app.route('/calendar/<int:year>/<int:month>', methods=['GET'])
@login_required
def view_calendar(year, month):
    helper = CalendarHelper(int(month), int(year))
    ((prev_month, prev_year), (next_month, next_year)) = helper.prev_and_next_month_and_year()
    helper.load_pages_in_range()
    helper.load_all_pagenames_set()
    return render_template(
        'view_calendar.html',
        toolbar_selection='calendar',
        pagename='calendar',
        breadcrumbs=helper.breadcrumbs(),
        calendar=helper,
        today=datetime.date.today(),
        prev_month=prev_month,
        prev_year=prev_year,
        next_month=next_month,
        next_year=next_year)

@app.route('/page_changes/<pagename>')
@login_required
def view_page_changes(pagename):
    per_page = 30
    page_str = request.args.get('page') or '1'
    page_number = max(1, min(100, int(page_str)))
    page = g.database.fetch_page(pagename) or Page(pagename)
    page_events1 = g.database.fetch_page_events(pagename, limit=per_page+1, skip=(page_number-1)*per_page)
    more_available = len(page_events1) > per_page
    page_events = page_events1[0:per_page]
    return render_template(
        'page_changes.html',
        toolbar_selection=('start' if pagename == 'start' else None),
        page=page,
        pagename=pagename,
        breadcrumbs=page.breadcrumbs(),
        page_number=page_number,
        events=page_events,
        more_available=more_available)

@app.route('/chat', methods=['GET'])
@login_required
def view_chat():
    helper = ChatroomHelper()
    if request.args.get('older') == '1':
        is_main_chat_view = False
        limit_in_seconds = 7*24*60*60
    else:
        is_main_chat_view = True
        limit_in_seconds = 2*24*60*60
    chat_pages = g.database.fetch_chat_pages(limit=500, limit_in_seconds=limit_in_seconds)
    return render_template(
        'view_chat.html',
        toolbar_selection='chat',
        pagename='chat',
        breadcrumbs=helper.breadcrumbs(),
        chat_pages=chat_pages,
        is_main_chat_view=is_main_chat_view,  # TODO: rename this
        helper=helper)

@app.route('/chat/fetch_latest', methods=['GET'])
@login_required
def fetch_latest_chats():
    helper = ChatroomHelper()
    limit_in_seconds = 2*24*60*60
    chat_pages = g.database.fetch_chat_pages(limit=500, limit_in_seconds=limit_in_seconds)
    return render_template(
        '_chat_messages.html',
        chat_pages=chat_pages,
        helper=helper)

@app.route('/chat', methods=['POST'])
@login_required
def post_chat():
    content = request.form['page_content'].strip()
    action = request.form['action']
    helper = ChatroomHelper()
    if action == 'save':
        helper.post_new_chat(content, current_user.user_id)
        g.database.create_notification(
            'chat',
            '{} posted a chat message'.format(current_user.username),
            current_user.user_id)
    elif action == 'preview':
        chat_pages = g.database.fetch_chat_pages()
        page = Page('chat_preview', content)
        return render_template(
            'view_chat.html',
            toolbar_selection='chat',
            pagename='chat',
            breadcrumbs=helper.breadcrumbs(),
            chat_pages=chat_pages,
            helper=helper,
            rendered_preview=page.content_as_markdown(),
            chat_content=page.content)
    return redirect(url_for('view_chat'))

@app.route('/chat/delete/<pagename>')
@login_required
def delete_chat_item(pagename):
    g.database.delete_chat_page(pagename)  # NOTE: this handles validation of pagename itself
    return redirect(url_for('view_chat'))


@app.route('/journal', methods=['GET'])
@login_required
def view_current_user_journal():
    now_local = current_local_timestamp()
    return redirect(url_for(
        'view_journal',
        username=current_user.username,
        year=now_local.year,
        month=now_local.month))

@app.route('/journal/<username>', methods=['GET'])
@login_required
def view_user_journal(username):
    user = g.database.fetch_user_by_username(username) or current_user
    now_local = current_local_timestamp()
    return redirect(url_for(
        'view_journal',
        username=user.username,
        year=now_local.year,
        month=now_local.month))

@app.route('/journal/<username>/<int:year>/<int:month>', methods=['GET'])
@login_required
def view_journal(username, year, month):
    now_local = current_local_timestamp()
    helper = JournalHelper()
    helper.load_all_pagenames_set()
    all_users = g.database.fetch_all_users()  # for user dropdown selector
    user_id = int(request.args.get('user_id', current_user.user_id))
    journal_user = g.database.fetch_user_by_id(user_id)
    entry_summary = helper.build_entry_summary(journal_user)
    if year == 0:
        year = now_local.year
    if month == 0:
        month = now_local.month
    current_summary_item = None
    for item in entry_summary:
        if item['year'] == year and item['month_index'] == month:
            current_summary_item = item
    if current_summary_item:
        pagenames = current_summary_item['pagenames']
    else:
        pagenames = []
    journal_pages = g.database.fetch_pages(pagenames)
    current_timestamp_string = now_local.strftime('%d-%b-%Y at %-I:%M') + now_local.strftime('%p').lower()
    return render_template(
        'view_journal.html',
        toolbar_selection='journal',
        pagename='journal',
        breadcrumbs=helper.breadcrumbs(journal_user, year, month),
        helper=helper,
        entry_summary=entry_summary,
        journal_pages=journal_pages,
        all_users=all_users,
        journal_user=journal_user,
        current_timestamp_string=current_timestamp_string,
        selected_year=year,
        selected_month=month)

@app.route('/journal', methods=['POST'])
@login_required
def post_journal_entry():
    content = request.form['entry_content'].strip()
    action = request.form['action']
    helper = JournalHelper()

    if action == 'save_with_system_time':
        save_entry = True
        entry_timestamp = current_local_timestamp()
    elif action == 'save_with_custom_time':
        save_entry = True
        entry_timestamp = dateutil.parser.parse(request.form['entry_timestamp'])
        # TODO: handle timestamp parsing errors
    elif action == 'preview':
        error("not yet implemented")
    else:
        save_entry = False

    if save_entry:
        helper.post_journal_entry(content, current_user, entry_timestamp)
        g.database.create_notification(
            'journal',
            '{} posted a new journal entry'.format(current_user.username),
            current_user.user_id)
    return redirect(url_for('view_journal',
                            username=current_user.username,
                            year=entry_timestamp.year,
                            month=entry_timestamp.month))
    
@app.route('/change_journal_timestamp/<pagename>', methods=['GET', 'POST'])
@login_required
def change_journal_timestamp(pagename):
    return 'not yet implemented'


@app.route('/files', defaults={'path': ''})
@app.route('/files/<path:path>')
@login_required
def view_directory(path):
    helper = FileHelper()
    subdirectories, file_details = helper.list_subdirectories_and_file_details(path)
    if subdirectories is None or file_details is None:
        # invalid path
        return redirect(url_for('view_directory', path=''))
    return render_template(
        'view_directory.html',
        toolbar_selection='files',
        breadcrumbs=helper.breadcrumbs(),
        pagename='files',
        helper=helper,
        current_path=path,
        parent_path=helper.parent_path(path),
        current_path_as_prefix=('' if path == '' else path+'/'),
        path_is_deletable=len(subdirectories) == 0 and len(file_details) == 0,
        subdirectories=subdirectories,
        file_details=file_details)

@app.route('/create_directory', methods=['POST'])
@login_required
def create_directory():
    helper = FileHelper()
    path = request.args.get('path')
    directory_name = request.form['directory_name']
    error = helper.create_directory(path, directory_name, current_user.user_id)
    if error:
        flash(error, 'error')
    return redirect(url_for('view_directory', path=path))

@app.route('/delete_directory', methods=['GET', 'POST'])
@login_required
def delete_directory():
    helper = FileHelper()
    path = request.args.get('path')
    error = helper.delete_directory(path, current_user.user_id)
    return redirect(url_for('view_directory', path=helper.parent_path(path)))

@app.route('/download_file/<filename>', methods=['GET'])
@login_required
def download_file(filename):
    helper = FileHelper()
    path = request.args.get('path') or ''
    attachment = request.args.get('attachment') == 'true'
    full_path_for_file = helper.full_path_for_file(path, filename)
    if full_path_for_file:
        return send_file(
            full_path_for_file,
            as_attachment=attachment,
            attachment_filename=filename)
    else:
        return redirect(url_for('view_directory', path=path))
    
@app.route('/upload_file', methods=['GET', 'POST'])
@login_required
def upload_file():
    helper = FileHelper()
    current_path = request.args.get('path') or ''
    if request.method == 'GET':
        return render_template(
            'upload_file.html',
            toolbar_selection='files',
            breadcrumbs=helper.breadcrumbs(),
            current_path=current_path,
            current_path_as_prefix=('' if current_path == '' else current_path+'/'))
    elif request.method == 'POST':
        # TODO: display errors
        error = None
        for uploaded_file in request.files.getlist('file'):
            if uploaded_file.filename != '':
                error = helper.save_uploaded_file(uploaded_file, current_path, current_user.user_id)
                if error:
                    break
                g.database.create_notification(
                    'file',
                    '{} uploaded {}/{}'.format(current_user.username, current_path, uploaded_file.filename),
                    current_user.user_id)
        return redirect(url_for('view_directory', path=current_path))

@app.route('/move_file', methods=['GET', 'POST'])
@login_required
def move_file():
    helper = FileHelper()
    path = request.args.get('path') or ''
    filename = request.args.get('filename') or ''
    all_directories = helper.list_all_directories()
    if request.method == 'GET':
        return render_template(
            'move_file.html',
            toolbar_selection='files',
            breadcrumbs=helper.breadcrumbs(),
            path=path,
            path_as_prefix=('' if path == '' else path+'/'),
            filename=filename,
            all_directories=all_directories)
    elif request.method == 'POST':
        new_filename = request.form['filename']
        new_directory = request.form['directory'].strip('/')
        # TODO: show errors
        error = helper.rename_or_move_file(
            path, filename, new_directory, new_filename, current_user.user_id)
        return redirect(url_for('view_directory', path=new_directory))

@app.route('/delete_file')
@login_required
def delete_file():
    helper = FileHelper()
    path = request.args.get('path') or ''
    filename = request.args.get('filename') or ''
    error = helper.delete_file(path, filename, current_user.user_id)
    if error is None:
        g.database.create_notification(
            'file',
            '{} deleted file {}/{}'.format(current_user.username, path, filename),
            current_user.user_id)
    return redirect(url_for('view_directory', path=path))
    
@app.route('/sitemap')
@login_required
def view_sitemap():
    page_infos = g.database.fetch_sitemap()
    return render_template(
        'view_sitemap.html',
        toolbar_selection='sitemap',
        pagename='sitemap',
        breadcrumbs=[('start', 'start', False), ('sitemap', 'sitemap', True)],
        page_infos=page_infos)

@app.route('/search', methods=['GET', 'POST'])
@login_required
def fulltext_search():
    per_page = 20
    page_str = request.args.get('page') or '1'
    page_number = max(1, min(100, int(page_str)))
    query = request.args.get('query') or ''
    sanitized_query = re.sub(r'[^\w\s\d]', '', query).strip()
    if len(sanitized_query) == 0:
        results = []
    else:
        results = g.database.fulltext_search(
            sanitized_query, per_page+1, (page_number-1)*per_page)
    more_available = len(results) > per_page
    results = results[0:per_page]
    return render_template(
        'search_results.html',
        pagename='search',
        query=sanitized_query,
        search_results=results,
        page_number=page_number,
        more_available=more_available)

@app.route('/notifications_json')
@login_required
def get_latest_notifications_json():
    cutoff_timestamp = request.args.get('cutoff')
    user_id = 123 # current_user.user_id
    notifications = g.database.fetch_notifications(user_id, cutoff_timestamp=cutoff_timestamp)
    return jsonify(notifications)

@app.route('/profile', methods=['GET'])
@login_required
def view_profile():
    return render_template(
        'view_profile.html',
        toolbar_selection='profile',
        pagename='profile',
        chatroom_helper=ChatroomHelper())

@login_required
@app.route('/profile', methods=['POST'])
def update_profile():
    # current_user.username = request.form['username'].strip()
    current_user.profile['notifications'] = request.form['notification_preference']
    current_user.profile['chat_color'] = request.form['chat_color']
    g.database.save_user_changes(current_user)
    flash('Profile updated.', 'profile_notice')
    return redirect(url_for('view_profile'))

@login_required
@app.route('/update_password', methods=['POST'])
def update_password():
    old_password = request.form['current_password']
    new_password = request.form['new_password']
    password_verify = request.form['password_verify']
    if new_password != password_verify:
        flash('New password does not match verification password.', 'password_error')
    elif g.database.change_user_password(current_user.user_id, old_password, new_password):
        flash('Password successfully changed.', 'password_notice')
    else:
        flash('Unable to update password.  Make sure you enter your old password correctly.', 'password_error')
    return redirect(url_for('view_profile'))

@login_required
@app.route('/admin', methods=['GET', 'POST'])
def site_admin():
    all_users = g.database.fetch_all_users()
    return render_template(
        'admin.html',
        pagename='admin',
        all_users=all_users)

@login_required
@app.route('/admin/create_user', methods=['POST'])
def create_user():
    g.database.create_user(
        request.form['username'],
        request.form['password'])
    return redirect(url_for('site_admin'))

@login_required
@app.route('/admin/reset_password/<int:user_id>')
def reset_password(user_id):
    g.database.reset_user_password(user_id)
    return redirect(url_for('site_admin'))

@login_required
@app.route('/admin/delete_user/<int:user_id>')
def delete_user(user_id):
    if user_id != current_user.user_id:
        g.database.delete_user_id(user_id)
    return redirect(url_for('site_admin'))
    
