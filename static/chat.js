

function pinewiki_chat_init() {
    window.setTimeout(pinewiki_chat_fetch_latest, 5000);
}

function pinewiki_chat_fetch_latest() {
    window.setTimeout(pinewiki_chat_fetch_latest, 5000);
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function () {
	if(xhr.readyState == XMLHttpRequest.DONE && xhr.status == 200) {
	    var container = document.getElementById('chat_post_container');
	    if(container)
		container.innerHTML = xhr.responseText;
	}
    };
    var url = '/chat/fetch_latest';
    xhr.open('GET', url, true);
    xhr.send();
}


window.addEventListener('DOMContentLoaded', pinewiki_chat_init, false);
