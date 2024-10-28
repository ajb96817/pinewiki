

function pinewiki_check_in_init() {
    window.setTimeout(pinewiki_check_in_fetch_latest, 5000);
}

function pinewiki_check_in_fetch_latest() {
    window.setTimeout(pinewiki_check_in_fetch_latest, 5000);
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function () {
	if(xhr.readyState == XMLHttpRequest.DONE && xhr.status == 200) {
	    var container = document.getElementById('check_in_container');
	    if(container)
		container.innerHTML = xhr.responseText;
	}
    };
    var url = '/check_in/fetch_latest';
    xhr.open('GET', url, true);
    xhr.send();
}


window.addEventListener('DOMContentLoaded', pinewiki_check_in_init, false);

