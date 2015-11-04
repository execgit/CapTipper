#!/usr/bin/env python

#
#          CapTipper is a malicious HTTP traffic explorer tool
#          By Omri Herscovici <omriher AT gmail.com>
#          http://omriher.com
#          @omriher
#
#          This file is part of CapTipper
#
#          CapTipper is a free software under the GPLv3 License
#

__author__ = 'Omri Herscovici'

import colorama
import sys
import time
import argparse
import parse_pcap
import gzip
import urlparse
import code
import logging
from cStringIO import StringIO

import CTCore
from CTConsole import console
from CTReport import Report
import CTPlugin

def main(args, pcap_file):
    CTCore.pcap_file = pcap_file[0]
    print("[A] Analyzing PCAP: " + CTCore.pcap_file)

    CTCore.b_use_short_uri = args.short_url # Display short URI paths
    CTCore.b_auto_ungzip = args.ungzip

    if(args.report is not None):
        CTCore.b_auto_ungzip = True

    parse_pcap.run(CTCore.pcap_file)

    if not CTCore.conversations:
        sys.exit("No HTTP conversations were found in PCAP file")

    print(CTCore.newLine + "[+] Traffic Activity Time: "),
    try:
        print(CTCore.activity_date_time)
    except:
        print "Couldn't retrieve time"

    print("[+] Conversations Found:" + CTCore.newLine)
    print CTCore.show_conversations()

    # If chosen just to dump files and exit
    if (args.dump is not None):
        try:
            CTCore.ungzip_all()
            CTCore.dump_all_files(args.dump[0],True)
        except Exception, ed:
            print ed
    # If chosen to create a report
    elif (args.report is not None):
        report = Report(CTCore.hosts, CTCore.conversations, CTCore.VERSION + " b" + CTCore.BUILD)
        report.CreateReport(args.report[0])
    else:
        CTPlugin.init_plugins()

if __name__ == "__main__":
    try:
        print CTCore.ABOUT
        colorama.init()

        parser = argparse.ArgumentParser(usage=CTCore.USAGE, add_help=False)
        parser.add_argument("-h", "--help", action='help', help='Print this help message and exit')
        parser.add_argument('-d','--dump', nargs=1, metavar='FOLDER PATH', help='Dump all files and exit', required=False)
        parser.add_argument('-short','--short-url',action="store_true", help='Display shortened URI paths', required=False)
        parser.add_argument('-r','--report', nargs=1, metavar='FOLDER PATH', help='Create JSON & HTML report', required=False)
        parser.add_argument('-g','--ungzip',action="store_false", help='Remove automatic response ungziping', required=False)

        args, pcap_file = parser.parse_known_args()

        if len(pcap_file) != 1:
            parser.print_help()
            sys.exit(0)
        else:
            main(args, pcap_file)

    except (KeyboardInterrupt, EOFError):
        print (CTCore.newLine + 'Exiting CapTipper')
    except Exception,e:
        print str(e)

    ## Console improvement stuff

    jsrun_logger = StringIO()
    logging.basicConfig(stream=jsrun_logger, level=logging.WARN)
    try:
        from ThugAPI import *
        import PyV8
        THUG =  "jsrun(x, ua=x, l=y)  run conversation x through JS evaluation\n"
        THUG += "                     with ua=user agent (default to ua in request) "
        THUG += "and l=log length (0 = print all)\n"
        THUG += "                     retains window object and JS context\n"
        THUG += "jw(x)                handle the window object, eg jw('location')\n"
        THUG += "jseval(x )           evaluate x with PyV8 with new or existing context"
    except ImportError:
        THUG = ""

    from CTCore import *
    from CTConsole import *
    from pydoc import pipepager
    c = console()
    _pager = lambda text: pipepager(text, 'less -R -X -F')
    def pager(text):
        if len(text.splitlines()) > 20:
            _pager(text)
        else:
            print text

    import readline, rlcompleter
    readline.parse_and_bind('tab:complete')

    import sys
    import re

    HEADERREGEX1 = 'GET (?P<path>[^ ]+) .+?\n(?:.+\n)*(?:^Referer: (?P<referer>.+)\n)(?:.+\n)*(?:^Host: (?P<host>.+))'
    HEADERREGEX2 = 'GET (?P<path>[^ ]+) .+?\n(?:.+\n)*(?:.+\n)*(?:^Host: (?P<host>.+))'
    HEADER_RE1 = re.compile(HEADERREGEX1, re.M|re.I)
    HEADER_RE2 = re.compile(HEADERREGEX2, re.M|re.I)

    # FIXME move into a file
    EKREGEX = {'8x8': ["[^ '\"]+.php\?id=[^ '\"]+"],
               # ^ fixme, bad regex, takes ages with some inputs
               'unknown': ['/wordpress/\?bf7N&utm_source='],
               'angler': [
            '/viewforum\.php(?=.*?\x3d[^\x26]*?[\x41-\x5a\x61-\x7a])(?=.*?[\x26\x3f](?:[\x74\x66]\x3d[^\x26]*?[^\x26\x30-\x39]|\x73\x69\x64\x3d(?![\x30-\x39\x41-\x46\x61-\x66]{32}(?:\x26|$))))\?(?:\x66=\d*?[^\d]|[^&=]+=(?:(?:&[^&=]+=)*?[^&]*?\d[^&]*?(?:&[^&=]+=)*)+&*)', 
            '/viewtopic\.php(?=.*?\x3d[^\x26]*?[\x41-\x5a\x61-\x7a])(?=.*?[\x26\x3f](?:[\x74\x66]\x3d[^\x26]*?[^\x26\x30-\x39]|\x73\x69\x64\x3d(?![\x30-\x39\x41-\x46\x61-\x66]{32}(?:\x26|$))))\?(?:\x74=\d*?[^\d]|[^&=]+=(?:(&[^&=]+=)*?[^&]*?\d[^&]*?(?:&[^&=]+=)*)+&*)', 
            'Set-Cookie: _PHP_SESSION_PHP=.+', 
            '[a-z]+{position\x3aabsolute\x3btop\x3a-?\d{1,}px\x3b[^\r\n]+<\/style><div\s*?class=\s*?[\x22\x27][a-z]+[\x22\x27]><iframe[^>]+src="([^"]+)"[^>]+>', 
            '/Referer\x3a\x20http\x3a\x2f+(?P<refhost>[^\x3a\x2f\r\n]+).*?\r\nHost\x3a\x20(?!(?:(?P=refhost)|forums?\.|www\.|boards?\.|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\r$|\x3a)))/',
            '(?:\/[a-z]{2,20})?\/search\.php\?[^&=]+=(?:(?:&[^&=]+=)*?[^&]*?\d[^&]*?(?:&[^&=]+=)*).+? ',
            '/(?=.*?(?:[A-Z]|[a-z]\d+[a-z]))(?:[a-z]{3,20})?\.php\?[a-z\d]{1,2}=(?![0-9]{5,}&|[A-Fa-f0-9]{32})[a-zA-Z0-9_-]+(?:&[a-z0-9]{1,2}=(?![0-9]{5,}(?:&|$)|[A-Fa-f0-9]{32})[a-zA-Z0-9_-]+){4,}(?:&[a-zA-Z0-9_=-]+)?',
                          ],
               'anglerjoomla': ['<iframe src="([^"]+)"[^>]+></iframe></div>\s+<!DOCTYPE'],
               'anglerwp': [
            '<body.+iframe src="([^"]+)',
            ],
               'nuclear': ['\/search\?q=(?=[A-Z&=\d]*?[a-z])(?=[a-zA-Z\d&=]*?[A-Za-z=&]\d[A-Za-z])(?=[a-zA-Z\d&=]*?[a-z\d][A-Z][A-Za-z\d])[A-Za-z0-9]+&[A-Za-z0-9]+=[A-Za-z0-9]+&[A-Za-z0-9]+=[A-Za-z0-9]+&[A-Za-z0-9]+=[A-Za-z0-9]+[&=A-Za-z0-9]*?\x2e{0,2}'],
               'dotkachef': ['^Location\x3a[^\r\n]+\/[A-Fa-f0-9]+\.js\?cp='],
               'cushion': ['/index\.php\?[a-z]=[A-Za-z0-9\/\+]*?(?:(?:N1cm[kw]|RpbWU)9|(?:zdXJ[ps]|0aW1l)P|c3Vy(?:aT|bD)|dGltZT)[A-Za-z0-9\/\+]+?(?:(?:N1cm[kw]|RpbWU)9|(?:zdXJ[ps]|0aW1l)P|c3Vy(?:aT|bD)|dGltZT)[A-Za-z0-9\/\+]+(?:(?:N1cm[kw]|RpbWU)9|(?:zdXJ[ps]|0aW1l)P|c3Vy(?:aT|bD)|dGltZT)[A-Za-z0-9\/\+]+={0,2}'],
               'nitoris': ['app_key=[a-f0-9]{32}'],
               }

    _o, objdata = list(), ''
    def make_objs():
        global _o, objdata, objects
        _o = [x.value for x in objects]
        objdata = ''.join(x and x or '' for x in _o)
    make_objs()
    def objs():
        global _o
        print "Total of %s objects:" % (len(_o))
        for i, x in enumerate(_o):
            if x:
                print "%s: %s..." % (i, repr(x.split('\n')[0][:50]))
            else:
                print "%s: empty" % (i)

    def o(x):
        try:
            return _o[x]
        except IndexError:
            print "No such object"
            pass
    
    def pa_retval(func, line, *args):
        c.retval = ''
        func(line, *args)
        pager(c.retval)
    def p_retval(func, line, *args):
        c.retval = ''
        func(line, *args)
        print c.retval

    convs = lambda: pa_retval(c.do_convs, 0)

    req = lambda x: p_retval(c.do_req, x)
    head = lambda x: p_retval(c.do_head, x)
    body = lambda x: p_retval(c.do_body, x)
    def res(x):
        c.retval = ''
        c.do_head(x)
        out = c.retval
        if o(x):
            c.retval = ''
            c.do_body(x)
            out += newLine + c.retval
        print out
    info = lambda x: p_retval(c.do_info, x)
    hashes = lambda x: p_retval(c.do_hashes, x)
    def hexdump(line, xor=None):
        pa_retval(c.do_hexdump, line, xor, "all")
    dump = lambda x: p_retval(c.do_dump, x)
    def ungz(x):
        global _o, objdata, objects
        p_retval(c.do_ungzip, x)
        make_objs()

    _scripts = []
    _iframes = []
    def get_iframes(x):
        global _iframes
        _iframes = c.do_iframes(x).tags
        iframes()
    def iframes():
        global _iframes
        out = ''
        for i, x in enumerate(_iframes):
            cont = ''
            if len(x) > 100:
                cont = '...'
            out += "%s: %s%s%s" % (i, x[:100], cont, newLine)
        pager(out)
    iframe = lambda x: _iframes[x]

    def get_scripts(x):
        global _scripts
        _scripts = c.do_iframes(x, 'script').tags
        scripts()
    def scripts():
        global _scripts
        out = ''
        for i, x in enumerate(_scripts):
            cont = ''
            if len(x) > 100:
                cont = '...'
            out += "%s: %s%s%s" % (i, x[:100], cont, newLine)
        pager(out)
    script = lambda x: _scripts[x]

    def _ek():
        global _o, EKREGEX
        out = ''

        for i, x in enumerate(_o):
            convi = conversations[i]
            headdata = HEADER_RE1.search(convi.req_head)
            if not headdata:
                headdata = HEADER_RE2.search(convi.req_head)
            if headdata:
                headdata = headdata.groupdict()

            if not x:
                x = ''
            x = convi.req_head + convi.res_head + x
            for typ in EKREGEX:
                for reg in EKREGEX[typ]:
                    data = re.findall(reg, x, re.M|re.I)
                    if data:
                        hosturl, dst, dsturl = '', '', ''
                        if headdata:
                            path = headdata.get('path')
                            hosturl = headdata.get('referer', '')
                            dst = headdata.get('host')
                            dsturl = 'http://%s%s' % (dst, path)
                            if not hosturl:
                                hosturl = convi.host
                        out += '%s: (%s) (%s) %s -> %s\n' % \
                               (typ, i, convi.server_ip_port, hosturl, dsturl)
                                                          
                        url = urlparse.urlparse(hosturl)
                        src = url.netloc
                        if not src:
                            src = hosturl
                        out += "Possible breached site %s directing to %s.\n" \
                               % (src, dst)

        return out
    ek = lambda: pager(_ek())

    regex = lambda x, y: re.findall(x, o(y), re.M|re.I)
    def search(text, objnum):
        out = ''
        if not text in o(objnum):
            print "Not found"
            return
        ind = 0
        for i in range(o(objnum).count(text)):
            ind += int(o(objnum)[ind:].index(text))
            if ind < 200:
                start = 0
            else:
                start = ind - 200
            if ind + 200 > len(o(objnum)):
                end = len(o(objnum))
            else:
                end = ind + 200

            out += o(objnum)[start:end] + newLine
            ind += 1
        pager(out)

    b64 = lambda x: x.decode('base64')
    p = lambda x: pager(x)
    _help = help

    # Making stuff accessible for people not used to Python can make your eyes bleed
    class Help(object):
        def __repr__(self):
            print """This is a normal Python shell with some special commands for your convenience.

Available commands:
convs()              show conversations
hosts()              show hosts in conversations

req(x)               show conversation x request
res(x)               show conversation x response (head and body)
head(x)              show conversation x response head
body(x)              show conversation x response body
info(x)              show conversation x infomation
hexdump(x, "xorkey") show hexdump of conversation x response body, with optional xor
dump("x filename")   dump conversation x response to filename
ungz(x)              zlib decode conversation x response (makes new object from ungz)

o(x)                 show raw object x from conversations
objdata              raw data from all objects (mainly useful for "text" in objdata etc.)
objs()               show object list
hashes(x)            show md5/sha1/sha256/sha512 hashes of object x

get_iframes(x)       searches iframes from conversation x response
iframe(y)            shows iframe y from previous search
get_scripts(x)       searches scripts from conversation x response
script(y)            shows script y from previous search

search("text", x)    searches for given text in conversation x response
regex(regexp, x)     does an arbitrary regexp search on conversation x response

beautify("text")     run any text thought jsbeautifier, eg. beautify(o(1))
p("text")            run any text through pager
b64("text")          base64 decode text

ek()                 show hits to exploit kits (ALPHA)

ids()                searchers IDS hits from pcap contents
hits()               shows hosts with IDS hits
i(z)                 shows IDS hit z where z is either conversation ID or ip:port (needs ids() invocation)

%s

_help                Normal python help""" % (THUG)
            return ''
        def __call__(self):
            self.__repr__()

    help = Help()

    # JS Stuff

    from jsbeautifier import beautify

    # IDS Stuff

    from subprocess import Popen, PIPE, STDOUT
    def run_command(cmd):
        p = Popen(cmd, stdout=PIPE, stderr=STDOUT,
                  shell=True, close_fds=True)
        return p.stdout.read(), p.returncode

    ruledata = ''
    venv = os.environ.get('VIRTUAL_ENV', '/')
    RULEFILE = os.path.join(venv, 'etc/local/captipper/rules')
    RULECMD = 'snort_pcap_test.sh %s "%s"'
                           
    JSCONFPATH = os.path.join(venv, "etc/local/thug/")

    _hits = dict()
    def ids():
        d, _ = run_command(RULECMD % (RULEFILE, 
                                      sys.argv[1].replace('"', '\\"')))

        DELIM = '=+' * 37
        d = d.split(DELIM)

        ruledata = file(RULEFILE).readlines()

        def find_rule(sid):
            for line in ruledata:
                if 'sid:%s' % (sid) in line:
                    return line

        rules = list()
        RULE_RE = re.compile(r'^(.+\[\*\*\].+)$', re.I)
        SID_RE = re.compile(r'\[\*\*\] \[\d+:(\d+)')

        for item in d:
            if '[**]' in item:
                rules.append(RULE_RE.findall(item)[0])

        for item in rules:
            time = item.split()[0]
            for hit in d:
                hit = RULE_RE.sub('', hit)
                if time in hit:
                    sid = SID_RE.findall(item)[0]
                    rule = find_rule(sid)
                    ips = re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+', hit)
                    conv_id = list()
                    sip = ''
                    for i, conv in enumerate(conversations):
                        for ip in ips:
                            if conv.server_ip == ip:
                                sip = ip
                                conv_id.append(i)
                    _hits.setdefault(ip, dict())
                    _hits[ip].setdefault('id', list()).extend(conv_id)
                    _hits[ip].setdefault('rules', list()).append(rule)
                    _hits[ip].setdefault('_hits', list()).append(hit.strip())
                    
        print "Found %s ips" % (len(_hits))

    def i(aid):
        if not _hits:
            print "No _hits found. Have you invoked ids()?"
        if not isinstance(aid, int):
            for rule, hit, _id in zip(_hits[aid]['rules'], 
                                      _hits[aid]['_hits'], _hits[aid]['id']):
                print "Rule:\n %s\nHit:\n %s\nId: %s" % (rule, hit[:1000], _id)
        else:
            for hit in _hits:
                if aid in _hits[hit]['id']:
                    for rule, hit in zip(_hits[hit]['rules'],
                                         _hits[hit]['_hits']):
                        print "Rule:\n %s\nHit:\n %s\n" % (rule, hit[:1000])
                    break

    def hits():
        if not _hits:
            print "No _hits found. Have you invoked ids()?"
        print ', '.join(_hits)

    def hosts():
        for i, conv in enumerate(conversations):
            print "%s: %s -> %s" % (i, conv.client_ip, conv.server_ip_port)

    import requests
    conversations_r = dict()
    for conv in conversations:
        url = url='http://{}{}'.format(conv.host, conv.uri)
        reqhead = requests.structures.CaseInsensitiveDict(conv.req_headerdict)
        _r = requests.Request(method=conv.method, url=url,
                               headers=reqhead)
        r = requests.Response()
        r.request = _r
        r.status_code = int(conv.res_num.split()[0])
        r.header = conv.res_head
        # Might be wrong
        r.raw = conv.res_body
        r._content = conv.res_body
        r.url = url
        conversations_r[url] = r

    _jw = None
    jsrun_out = ''
    def jsrun(aid, ua=None, l=200):
        global jsrun_logger, jsrun_out
        jsrun_logger.seek(0)

        if not o(aid):
            print "Object {} has no content".format(aid)
            return
        global _jw
        t = ThugAPI('', configuration_path=JSCONFPATH)
        t.set_no_fetch()
        t.log_init('')
        url = 'http://{}{}'.format(conversations[aid].host, 
                                   conversations[aid].uri)
        w = t.window_from_file(o(aid), url, offline_content=conversations_r,
                               max_len=l)
        # Customise referer and user-agent, the latter is not
        # especially pretty but what can you do - we cannot have
        # personality files for everything we see
        t.set_referer(conversations[aid].referer)
        if ua:
            w._navigator.personality['userAgent'] = ua
        else:
            w._navigator.personality['userAgent'] \
                = conversations[aid].user_agent
        t.run(w)
        _jw = w
        jsrun_out = jsrun_logger.getvalue()
        p(jsrun_out)

    def jseval(code):
        global _jw
        if not _jw:
            ctxt = PyV8.JSContext()
            ctxt.enter()
            retval = ctxt.eval(code)
            ctxt.leave()
        else:
            k = PyV8.JSLocker()
            k.enter()
            _jw.context.enter()
            retval = _jw.context.eval(code)
            _jw.context.leave()
            k.leave()
        return retval

    # The Window object is a JSClass so you should only 
    def jw(code):
        if not _jw:
            print "No active window object, use jsrun first"
            return
        k = PyV8.JSLocker()
        k.enter()
        _jw.context.enter()
        retval = eval("_jw.{}".format(code))
        _jw.context.leave()
        k.leave()
        return retval

    # ek()

    code.interact('', local=locals())
