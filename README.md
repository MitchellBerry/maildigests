# MailDigests

Combines all emails fitting a specified search criteria, configured for gmail. Processes a maximum of 50 messages by default.

## Install
* Enable Gmail API access, as shown in **Step 1** of this guide:
https://developers.google.com/gmail/api/quickstart/python

* Install the python client 
    ```shell
    pip install --upgrade google-api-python-client
    ```
* Install maildigests
    ```shell
    git clone https://github.com/MitchellBerry/maildigests.git
    ```
## Usage

Intended to be used as a command line tool in combination with a scheduler.
```bash
python maildigests.py --help

usage: maildigests.py [-h] [-s SEARCH] [-d DEPTH] [-l LOGLEVEL] [-f LOGFILE]
                      [-p PLAINTEXT] [-t TOPIC]

optional arguments:
  -h, --help            show this help message and exit
  -s SEARCH, --search SEARCH
                        Search query, same response as querying Gmail search
                        box, can use advanced search operators. Check messages
                        returned by the search response if getting unwanted
                        results and adjust as necessary. Full list of
                        operators:
                        https://support.google.com/mail/answer/7190?hl=en
  -d DEPTH, --depth DEPTH
                        Maximum number of messages per digest, most recent
                        emails are processed first. Default is 50
  -l LOGLEVEL, --loglevel LOGLEVEL
                        Options: "debug", "info", "error", no logging will
                        occur with any other value. Default is info
  -f LOGFILE, --logfile LOGFILE
                        Set True to save log to file. Default is False
  -p PLAINTEXT, --plaintext PLAINTEXT
                        Process as plain text email instead of html. Default
                        is False
  -t TOPIC, --topic TOPIC
                        Email subject line
```

Example

```bash
python maildigests.py -s "from:googlealerts-noreply@google.com" -d 10 -t "Alerts Digest"
```
Google API daily rate limits: https://developers.google.com/gmail/api/v1/reference/quota

Search query supports advanced operators, full list can be found here: https://support.google.com/mail/answer/7190?hl=en



