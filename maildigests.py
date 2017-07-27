import os
import sys
import base64
import argparse
import httplib2
import logging
import logging.handlers
from apiclient import errors
from apiclient import discovery
from oauth2client import tools
from oauth2client import client
from oauth2client.file import Storage
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# api rate limits: https://developers.google.com/gmail/api/v1/reference/quota

LOGPATH = 'maildigests.log'
MAX_LOG_SIZE = 2**16  # Bytes. Default 64KB

APPLICATION_NAME = 'Mail Digests'  # Name registered with Google OAuth
CLIENT_SECRET_FILE = 'client_secret.json'  # Keep secure
SCOPES = 'https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.modify'  # OAuth Pop-up

SEARCH_HELP = """
Search query, same response as querying Gmail search box, can use advanced search operators.
Check messages returned by the search response if getting unwanted results and adjust as necessary.
Full list of operators: https://support.google.com/mail/answer/7190?hl=en
"""
DEPTH_HELP = 'Maximum number of messages per digest, most recent emails are processed first. Default is 50'
LOG_LEVEL_HELP = 'Options: "debug", "info", "error", no logging will occur with any other value. Default is info'
LOGFILE_HELP = 'Set True to save log to file. Default is False'
PLAINTEXT_HELP = 'Process as plain text email instead of html. Default is False'
TOPIC_HELP = 'Email subject line'


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--search', default="'Placeholder. Please make a search query!'", help=SEARCH_HELP)
    parser.add_argument('-d', '--depth', default=50, help=DEPTH_HELP, type=int)
    parser.add_argument('-l', '--loglevel', default='info', help=LOG_LEVEL_HELP)
    parser.add_argument('-f', '--logfile', default=False, help=LOGFILE_HELP)
    parser.add_argument('-p', '--plaintext', default=False, help=PLAINTEXT_HELP)
    parser.add_argument('-t', '--topic', default='MailDigest', help=TOPIC_HELP)
    return parser.parse_args()


def initialise():
    args = parse_args()
    loglevel = get_log_lvl(args.loglevel)
    log = logging.getLogger('digests')
    if args.logfile:
        filehandler = logging.handlers.RotatingFileHandler(LOGPATH, maxBytes=MAX_LOG_SIZE, backupCount=1)
        filehandler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%m-%d %H:%M'))
        log.addHandler(filehandler)
    streamhandler = logging.StreamHandler(sys.stdout)
    log.addHandler(streamhandler)
    log.setLevel(loglevel)
    return args, log


def get_log_lvl(level):
    levels = {'debug': logging.DEBUG, 'info': logging.INFO, 'error': logging.ERROR}
    try:
        return levels[level.lower()]
    except (KeyError, AttributeError, TypeError):
        return 50


def get_credentials():
    home_dir = os.path.expanduser('~')
    credential_dir = os.path.join(home_dir, '.credentials')
    if not os.path.exists(credential_dir):
        os.makedirs(credential_dir)
    credential_path = os.path.join(credential_dir, 'gmail-credentials.json')
    store = Storage(credential_path)
    credentials = store.get()
    if not credentials or credentials.invalid:
        flow = client.flow_from_clientsecrets(CLIENT_SECRET_FILE, SCOPES)
        flow.user_agent = APPLICATION_NAME
        credentials = tools.run_flow(flow, store)
        print('Storing credentials to ' + credential_path)
    return credentials


class MemCache(object):
    """ get_service() caching error fix - https://github.com/google/google-api-python-client/issues/325"""
    cache = {}
    def get(self, url):
        return MemCache.cache.get(url)
    def set(self, url, content):
        MemCache.cache[url] = content


def get_service():
    credentials = get_credentials()
    http = credentials.authorize(httplib2.Http())
    return discovery.build('gmail', 'v1', http=http, cache=MemCache())


def messages_by_query(service, depth, query=''):
    log = logging.getLogger('digests')
    messages = []
    try:
        response = service.users().messages().list(userId='me', q=query).execute()
        if 'messages' in response:
            messages.extend(response['messages'])
        while 'nextPageToken' in response:
            page_token = response['nextPageToken']
            response = service.users().messages().list(userId='me', q=query, pageToken=page_token).execute()
            messages.extend(response['messages'])
    except IndexError:
        return messages
    except errors.HttpError as e:
        log.exception(e)
    return messages[:depth]


def get_message(service, msg_id):
    try:
        message = service.users().messages().get(userId='me', id=msg_id).execute()
        return message
    except errors.Error as e:
        logging.exception('Error retrieving message\n %s' % e)


def parse_payload(msg):
    try:
        return msg['payload']['parts']
    except KeyError:
        return [msg['payload']]


def make_message(sender, to, subject):
    message = MIMEMultipart('alternative')
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    return message


def add_email(message, text):
    message.attach(MIMEText(text, 'html'))
    return message


def get_raw(message):
    return {'raw': base64.urlsafe_b64encode(message.as_string().encode()).decode('utf-8')}


def insert_message(service, user_id, message):
    try:
        return service.users().messages().insert(userId=user_id, body=message).execute()
    except errors.HttpError as e:
        logging.exception(e)


def get_payload(service, msgid):
    msg = get_message(service, msgid)
    return parse_payload(msg)


def modify_message(service, userid, msgid, msglabels):
    try:
        message = service.users().messages().modify(userId=userid, id=msgid, body=msglabels).execute()
        return message
    except errors.HttpError as e:
        log = logging.getLogger('digests')
        log.exception(e)


def preformat_html(htmlstring):
    return '<pre>%s</pre>' % htmlstring


def process_payload(payload, plaintext=False):
    decoded = ''
    for part in payload:
        if part['mimeType'] == 'application/pgp-signature':
            continue
        elif part['mimeType'] == 'text/html':
            try:
                b64 = part['body']['data']
                decoded = base64.urlsafe_b64decode(b64).decode()
                if not plaintext:
                    break
            except KeyError:
                decoded = ''
        else:
            try:
                b64 = part['body']['data']
                decoded = preformat_html(base64.urlsafe_b64decode(b64).decode())
                if plaintext:
                    break
            except KeyError:
                decoded = ''
    if not decoded:
        log = logging.getLogger('digests')
        log.debug(payload)
    return decoded


def combine_messages(service, messagelist, search, plaintext):
    log = logging.getLogger('digests')
    if messagelist:
        out = ''
        for message in messagelist:
            msgid = message['id']
            payload = get_payload(service, msgid)
            try:
                labelsdata = get_message(service, msgid)
                labels = labelsdata['labelIds']
                if 'SENT' in labels:
                    labels.remove('SENT')
                out += process_payload(payload, plaintext=plaintext)
                trashmsg = modify_message(service, 'me', message['id'],
                                          {'removeLabelIds': labels, 'addLabelIds': ['TRASH']})
                log.debug('Trashed msg: %s' % trashmsg)
            except KeyError:
                info = 'Message: %s - Ignored file attachment' % message['id']
                out += info
                log.debug(info)
            except TypeError as e:
                log.exception(e)
        return out
    else:
        log.error('No messages found: %s' % search)
        return ''


def send_digest(service, subject, out, messagelist, log):
    digestmsg = make_message('me', 'me', subject=subject)
    emailtosend = add_email(digestmsg, out)
    inserted = insert_message(service, 'me', get_raw(emailtosend))
    result = modify_message(service, 'me', inserted['id'],
                            {'removeLabelIds': [], 'addLabelIds': ['UNREAD', 'INBOX']})
    log.info('Processed %s messages' % len(messagelist))
    log.debug('Digest Message: %s' % result)


def digest():
    """Combines all emails returned from search query to a specified depth, sends to inbox"""
    args, log = initialise()
    log.info('Search Query: %s\nDepth: %s\nSubject: %s' % (args.search, args.depth, args.topic))
    service = get_service()
    messagelist = messages_by_query(service, args.depth, args.search)
    messagelist.reverse()
    digestmsg = combine_messages(service, messagelist, args.search, args.plaintext)
    send_digest(service, args.topic, digestmsg, messagelist, log)


if __name__ == '__main__':
    digest()
