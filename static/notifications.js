


function pinewiki_notifications_init() {
    // TODO: setup chat refresh timer if on chat page

    //window.setTimeout(pinewiki_request_notifications, 1000);
    pinewiki_request_notifications();
}


function pinewiki_request_notifications() {
    window.setTimeout(pinewiki_request_notifications, 5000);
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function () {
	if(xhr.readyState == XMLHttpRequest.DONE && xhr.status == 200) {
	    var parsed = JSON.parse(xhr.responseText);
	    pinewiki_process_notifications(parsed);
	}
    };
    var cutoff = pinewiki_notification_cutoff_from_cookies();
    var url = '/notifications_json';
    if(cutoff)
	url = url + '?cutoff=' + cutoff;
    xhr.open('GET', url, true)
    xhr.send();
}


function pinewiki_notification_cutoff_from_cookies() {
    var pieces = document.cookie.split(';');
    for(var i = 0; i < pieces.length; i++) {
	var kv = pieces[i].split('=');
	if(kv.length == 2 && kv[0].trim() == 'notification_cutoff')
	    return kv[1].trim();
    }
    return null;
}


function pinewiki_process_notifications(notifications) {
    if(notifications.length == 0)
	return;
    var main_notification = notifications[0];
    document.cookie = 'notification_cutoff=' + main_notification.timestamp + '; path=/';
    new Notification('Pinewiki', { 'body': main_notification.message });
}


window.addEventListener('DOMContentLoaded', pinewiki_notifications_init, false);


