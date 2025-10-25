

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
