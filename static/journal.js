

function enable_journal_entry() {
  document.getElementById('new_entry_form').style.display = 'block';
  document.getElementById('new_entry_button').style.display = 'none';
  document.getElementById('journal_navigation').style.display = 'none';
  document.getElementById('entry_content_textarea').focus();
}

function disable_journal_entry() {
  document.getElementById('new_entry_form').style.display = 'none';
  document.getElementById('new_entry_button').style.display = 'block';
  document.getElementById('journal_navigation').style.display = 'block';
}

function toggle_journal_entry(element_id) {
  let entry_element = document.getElementById(element_id);
  if(entry_element)
    entry_element.classList.toggle('expanded');
}

function expand_or_collapse_journal_comment_area(comment_area_id, journal_commands_id, expand) {
  let comment_area_element = document.getElementById(comment_area_id);
  if(comment_area_element)
    comment_area_element.style.display = expand ? 'block' : 'none';
  let commands_element = document.getElementById(journal_commands_id);
  if(commands_element)
    commands_element.style.display = expand ? 'none' : 'block';
}

