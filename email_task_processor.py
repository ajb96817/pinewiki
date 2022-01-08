#!/bin/env python3

import json
import redis
import time

from smtplib import SMTP, SMTP_SSL
from email.mime.text import MIMEText


REDIS_HOST = 'localhost'
REDIS_PORT = 6379


def go():
    redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT)
    log('Starting server.')
    while True:
        process_next_task(redis_client)
        # try:
        #     process_next_task(redis_client)
        # except Exception as exc:
        #     log('Error sending email: {}'.format(exc))
        
def process_next_task(redis_client):
    _, task_json = redis_client.blpop('email_task_queue')
    task = json.loads(task_json)
    log('Sending email: {}'.format(task))
    smtp_class = SMTP_SSL if task['use_ssl'] else SMTP
    msg = MIMEText(task['body'])
    msg['Subject'] = task['subject']
    msg['From'] = task['sender']
    msg['To'] = task['recipients'][0]
    with smtp_class(host=task['smtp_hostname'], port=task['smtp_port']) as smtp:
        smtp.login(task['username'], task['password'])
        smtp.sendmail(task['sender'], task['recipients'], msg.as_string())
        log('Email sent successfully.')
        
def log(msg):
    time_str = time.strftime('%Y-%d-%b %H:%M:%S', time.localtime())
    print('[{}]: {}'.format(time_str, msg))

go()

