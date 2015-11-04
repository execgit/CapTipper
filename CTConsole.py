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

import StringIO
import cmd
import os
import time
import hashlib
import sys

import CTCore
from CTCore import hexdump
from CTCore import colors
from CTCore import msg_type
from CTServer import server
from pescanner import PEScanner

newLine = os.linesep
DEFAULT_BODY_SIZE = 256

def get_id_size(line):
    l = line.split(" ")
    size = DEFAULT_BODY_SIZE
    if (len(l) > 1):
        size = l[1]

    id = int(l[0])
    return id, size

def get_head(id):
    header = CTCore.conversations[int(id)].res_head
    return header


SHOW_LEN_AROUND = 25
REPLACE_LIST = ['\r','\n']
def find_pattern(content, pattern):
    import re
    return_results = []
    regex = re.compile(pattern, re.IGNORECASE)
    results = regex.finditer(content)
    for result in results:
        match = result.group()
        if (result.start() - SHOW_LEN_AROUND) < 0:
            start = 0
        else:
            start = result.start() - SHOW_LEN_AROUND

        if (result.end() + SHOW_LEN_AROUND) > len(content):
            end = len(content)
        else:
            end = result.end() + SHOW_LEN_AROUND

        before_match = content[start:result.start()]
        after_match = content[result.end():end]

        for rep in REPLACE_LIST:
            before_match = before_match.replace(rep, "")
            after_match = after_match.replace(rep, "")

        result_line = before_match + colors.STRONG_BRIGHT + match + colors.NORMAL_BRIGHT + after_match + colors.END

        lineno = content.count('\n', 0, result.start()) + 1
        return_results.append(" ({},{}) : ".format(str(lineno), str(result.start())) + result_line)
    return return_results

def find_end_of_block(response, offset):
    index = response.find("{",offset)
    braces_c = 1
    while (braces_c > 0):
        index += 1
        char = response[index]
        if char == "{":
            braces_c += 1
        elif char == "}":
            braces_c -= 1

    return index - offset + 1

def get_bytes(response,offset,length_or_eob):
    if (length_or_eob.lower() == "eob"):
        length = find_end_of_block(response,offset)
    else:
        length = int(length_or_eob)

        if offset > len(response):
            print " Offset {} is not in range, object size is {}".format(str(offset), str(len(response)))

        if offset + length > len(response):
            length = len(response) - offset

    return response[offset:offset+length], length

def in_range(id, list_type='objects'):
    listname = getattr(CTCore, list_type)
    if int(id) >= len(listname) or int(id) < 0:
        print "   ID number " + str(id) + " isn't within range of " + list_type + " list"
        return False

    return True

def check_path(path,type="file"):
    directory = os.path.dirname(path)
    if type == "file" and os.path.isdir(path):
        CTCore.alert_message("Please specify a full path and not a folder",msg_type.ERROR)
        return False

    if not os.path.isdir(directory):
        print newLine + " Directory {} doesn't exists. Create? (Y/n):".format(directory),
        ans = raw_input()
        if ans.lower() == "y" or ans == "":
            os.makedirs(directory)
            return True
        else:
            return False
    else:
        return True

class console(object):
    """CapTipper console interpreter."""

    prompt = colors.SKY + 'CT> ' + colors.END
    intro = "Starting CapTipper Interpreter" + newLine + \
            "Type 'open <conversation id>' to open address in browser" + newLine + \
            "Type 'hosts' to view traffic flow" + newLine + \
            "Type 'help' for more options" + newLine
    retval = ""

    def __init__(self):
        super(console, self).__init__()

    def emptyline(self):
        return

    def precmd(self, line):
        if line == 'EOF':
            return 'exit'
        else:
            try:
                if CTCore.console_output:
                    self.output_log.write(line)
            except Exception, e:
                print e

            return line

    def postcmd(self, stop, line):
        print self.retval
        self.retval = ''
        return False

    def postloop(self):
        if (CTCore.web_server_turned_on):
            CTCore.web_server.shutdown()
        if self.use_rawinput:
            print newLine + "Leaving CapTipper... Good Bye!"

    def do_body(self, line):
        try:
            line = str(line)
            l = line.split(" ")
            if (l[0] == ""):
                self.help_body()
            else:
                id, size = get_id_size(line)
                response, size = CTCore.get_response_and_size(id, size)
                name = CTCore.get_name(id)
                self.retval = "Displaying body of object {} ({}) [{} bytes]:".format(id, name, size)
                CTCore.show_errors()
                self.retval += newLine + response
        except Exception,e:
            print str(e)


    def help_body(self):
        self.retval = newLine + "Displays the text representation of the body"
        self.retval += newLine + "Usage: body <conv_id> [size=" + str(DEFAULT_BODY_SIZE) + "]"
        self.retval += "       use 'all' as size to retrieve entire body"


    def do_log(self, line):
        try:
            line = str(line)
            if (len(CTCore.request_logs) > 0):
                for l in CTCore.request_logs:
                    self.retval += l
            else:
                self.retval += " No previous web server entries"
        except Exception,e:
            print str(e)

    def help_log(self):
        self.retval = newLine + "Displays the web server's Log"
        self.retval += newLine + "Usage: log"

    def do_dump(self,line):
        try:
            line = str(line)
            l = line.split(" ")
            if len(l) < 2:
                self.help_dump()
            else:
                if l[0].lower() == "all":
                    dump_exe = True
                    if len(l) > 2 and l[2].lower() == "-e":
                        dump_exe = False
                    self.retval += CTCore.dump_all_files(l[1], dump_exe)
                else:
                    id = l[0]
                    path = l[1]
                    if check_path(path, type="file"):
                        self.retval += CTCore.dump_file(id, path)

        except Exception,e:
            return str(e)

    def help_dump(self):
        self.retval = newLine + "Dumps the object file to a given folder"
        self.retval += newLine + "Usage: dump <conv_id> <path> [-e]" + newLine
        self.retval += "Options:"
        self.retval += "   -e       - ignores executables" + newLine
        self.retval += "Example: dump 4 c:" + chr(92) + "files" + chr(92) + "index.html"
        self.retval += "         Dumps object 4 to given path" + newLine
        self.retval += "Example: dump all c:" + chr(92) + "files"
        self.retval += "         Dumps all files to folder by their found name" + newLine
        self.retval += "Example: dump all c:" + chr(92) + "files -e"
        self.retval += "         Dumps all files to folder by their found name, without EXE files" + newLine

    def _xor(self, data, key):
        lkey = len(key)
        out = ''
        for i, x in enumerate(data):
            out += chr(ord(x) ^ ord(key[i % lkey]))
        return out

    def do_hexdump(self, line, xor=None, custsize=None):
        try:
            line = str(line)
            l = line.split(" ")
            if (l[0] == ""):
                self.help_hexdump()
            else:
                id, size = get_id_size(line)
                if custsize:
                    size = custsize
                response, size = CTCore.get_response_and_size(id, size)
                name = CTCore.get_name(id)
                self.retval = "Displaying hexdump of object {} ({}) body [{} bytes]:".format(id, name, size)
                self.retval += newLine + hexdump(response) + newLine
        except Exception,e:
            self.retval = str(e)

    def help_hexdump(self):
        self.retval = "Display hexdump of given object"
        self.retval += newLine + "Usage: hexdump <conv_id> [size=" + str(DEFAULT_BODY_SIZE) + "]"
        self.retval += "       use 'all' as size to retrieve entire body"

    def do_head(self,line):
        try:
            line = str(line)
            l = line.split(" ")
            if (l[0] == ""):
                self.help_head()
            else:
                id = int(l[0])
                header = get_head(id)
                name = CTCore.get_name(id)

                self.retval = "Displaying header of object {} ({}):".format(str(id), name)
                self.retval += newLine + header
        except Exception,e:
            self.retval = str(e)

    def help_head(self):
        self.retval = newLine + "Display header of response"
        self.retval += newLine + "Usage: head <conv_id>"

    def do_convs(self,line):
        line = str(line)
        self.retval = "Conversations Found:" + newLine
        self.retval += CTCore.show_conversations()

    def help_convs(self):
        self.retval = newLine + "Display the conversations found"
        self.retval += newLine + "Usage: convs"

    def do_objects(self,line):
        self.retval = CTCore.show_objects()

    def help_objects(self):
        self.retval = newLine + "Display all objects, found or created"
        self.retval += newLine + "Usage: objects"

    def do_hosts(self,line):
        self.retval = "Found Hosts:" + newLine
        self.retval += CTCore.show_hosts()

    def help_hosts(self):
        self.retval = newLine + "Display the hosts found in pcap and their URI's"
        self.retval += newLine + "Usage: hosts"

    def do_info(self,line):
        try:
            line = str(line)
            l = line.split(" ")
            if (l[0] == ""):
                self.help_info()
            else:
                id = l[0]
                if in_range(id, list_type='conversations'):
                    conv_obj = CTCore.conversations[int(id)]

                    self.retval = "Info of conversation {}: ".format(str(id))
                    self.retval += newLine + \
                          " SERVER IP   : " + conv_obj.server_ip_port
                    self.retval += " TIME        : " + time.strftime('%a, %x %X', time.gmtime(int(conv_obj.req_microsec)))
                    self.retval += " HOST        : " + conv_obj.host
                    self.retval += " URI         : " + conv_obj.uri
                    self.retval += " REFERER     : " + conv_obj.referer
                    self.retval += " METHOD      : " + conv_obj.method
                    self.retval += " RESULT NUM  : " + conv_obj.res_num
                    self.retval += " RESULT TYPE : " + conv_obj.res_type
                    self.retval += " FILE NAME   : " + conv_obj.filename.rstrip()
                    if conv_obj.magic_name != "":
                        self.retval += " MAGIC       : " + conv_obj.magic_name + " ({})".format(conv_obj.magic_ext)
                    self.retval += " LENGTH      : " + str(conv_obj.res_len) + " B" + newLine
        except Exception,e:
            self.retval = str(e)

    def help_info(self):
        self.retval = newLine + "Display info on object"
        self.retval += newLine + "Usage: info <conv_id>"

    def do_client(self,line):
        try:
            line = str(line)
            self.retval = newLine + "Client Info: " + newLine
            for key, value in CTCore.client.get_information().iteritems():
                self.retval += " {0:17}:  {1}".format(key, value)
        except Exception,e:
            self.retval = str(e)

    def help_client(self):
        self.retval = newLine + "Displays information about the client"
        self.retval += newLine + "Usage: client"

    def do_ungzip(self,line):
        try:
            line = str(line)
            l = line.split(" ")
            if (l[0] == ""):
                self.help_ungzip()
            else:
                if l[0].lower() == "all":
                    CTCore.ungzip_all()
                else:
                    id = int(l[0])
                    if in_range(id):
                        obj_num, name = CTCore.ungzip_and_add(id)
                        if obj_num != -1:
                            CTCore.conversations[int(id)].decoded = int(obj_num)
                            self.retval = " GZIP Decompression of object {} ({}) successful!".format(str(id), name)
                            self.retval += " New object created: {}".format(obj_num) + newLine
                        else:
                            CTCore.show_errors()
        except Exception,e:
            self.retval = str(e)

    def help_ungzip(self):
        self.retval = newLine + "Decompress gzip compression"
        self.retval += newLine + "Usage: ungzip <conv_id>"

    def do_exit(self, line):
        if (CTCore.web_server_turned_on):
            CTCore.web_server.shutdown()
        return True

    def do_ziplist(self, line):
        try:
            line = str(line)
            import zipfile
            l = line.split(" ")
            if (l[0] == ""):
                self.help_ziplist()
            else:
                id, size = get_id_size(line)
                if in_range(id):
                    response, size = CTCore.get_response_and_size(id, "all")
                    name = CTCore.get_name(id)
                    fp = StringIO.StringIO(response)
                    fp.write(response)
                    zfp = zipfile.ZipFile(fp, "r")
                    self.retval = " " + str(len(zfp.namelist())) + \
                                  " Files found in zip object {} ({}):".format(
                                      str(id),name) + newLine

                    for cnt, fl in enumerate(zfp.namelist()):
                        self.retval += " [Z] " + str(cnt + 1) + " : " + fl
                        cnt += 1
                    self.retval += newLine
        except Exception,e:
            self.retval = "Error unzipping object: " + str(e)

    def help_ziplist(self):
        self.retval = newLine + "Lists files inside zip object"
        self.retval += newLine + "Usage: ziplist <conv_id>"

    def do_iframes(self,line,tag="iframe"):
        try:
            line = str(line)
            l = line.split(" ")
            if (l[0] == ""):
                self.help_resp()
            else:
                id, size = get_id_size(line)
                response, size = CTCore.get_response_and_size(id, "all")
                name = CTCore.get_name(id)

                parser = CTCore.srcHTMLParser(tag)
                self.retval = "Searching for iframes in object {} ({})...".format(str(id),name)
                parser.feed(response)
                self.retval += "{} found{}".format(len(parser.tags), newLine)
                return parser
        except Exception,e:
            self.retval = str(e)

    def help_iframes(self):
        self.retval = newLine + "Finds iframes in html/js files"
        self.retval += newLine + "Usage: iframes <obj_id>"

    def do_vt(self,line):
        try:
            line = str(line)
            l = line.split(" ")
            if (l[0] == ""):
                self.help_vt()
            else:
                if not CTCore.VT_APIKEY:
                    print newLine + "No Virus Total API key found, please enter your API key:",
                    CTCore.VT_APIKEY = raw_input()

                id = int(l[0])
                body, sz = CTCore.get_response_and_size(id, "all")
                name = CTCore.get_name(id)

                self.retval = " VirusTotal result for object {} ({}):".format(str(id),name) + newLine

                hash = hashlib.md5(StringIO.StringIO(body).getvalue()).hexdigest()
                vtdata = CTCore.send_to_vt(hash, CTCore.VT_APIKEY)
                if vtdata[0] != -1:
                    jsonDict = vtdata[1]
                    if jsonDict.has_key('response_code'):
                        if jsonDict['response_code'] == 1:
                            if jsonDict.has_key('scans') and jsonDict.has_key('scan_date') \
                            and jsonDict.has_key('total') and jsonDict.has_key('positives') and jsonDict.has_key('permalink'):
                                self.retval += " Detection: {}/{}".format(jsonDict['positives'], jsonDict['total'])
                                self.retval += " Last Analysis Date: {}".format(jsonDict['scan_date'])
                                self.retval += " Report Link: {}".format(jsonDict['permalink']) + newLine
                                if jsonDict['positives'] > 0:
                                    self.retval += " Scan Result:"

                                    for av in jsonDict['scans']:
                                        av_res = jsonDict['scans'][av]
                                        if av_res.has_key('detected') and av_res.has_key('version') and av_res.has_key('result') and av_res.has_key('update'):
                                            if av_res['detected']:
                                                self.retval += "\t{}\t{}\t{}\t{}".format(av, av_res['result'], av_res['version'], av_res['update'])
                            else:
                                self.retval += " Missing elements in Virus Total Response"
                        else:
                            self.retval += " File not found in VirusTotal"

                    else:
                        self.retval += " Response from VirusTotal isn't valid"
                else:
                    self.retval += vtdata[1]

                self.retval += newLine
        except Exception,e:
            self.retval = str(e)

    def help_vt(self):
        self.retval = newLine + "Checks file's md5 hash in virus total"
        self.retval += newLine + "Usage: vt <obj_id>"

    def do_hashes(self,line):
        try:
            line = str(line)
            l = line.split(" ")
            if (l[0] == ""):
                self.help_hashes()
            else:
                id = int(l[0])
                body, sz = CTCore.get_response_and_size(id, "all")
                name = CTCore.get_name(id)

                self.retval = " Hashes of object {} ({}):".format(str(id),name) + newLine

                for alg in hashlib.algorithms:
                    hashfunc = getattr(hashlib, alg)
                    hash = hashfunc(StringIO.StringIO(body).getvalue()).hexdigest()
                    self.retval += " {0:8}  :   {1}".format(alg, hash)

                self.retval += newLine

        except Exception,e:
            self.retval = str(e)

    def help_hashes(self):
        self.retval = newLine + "Prints available hashes of object"
        self.retval += newLine + "Usage: hashes <obj_id>"

    def do_peinfo(self, line):
        try:
            line = str(line)
            l = line.split(" ")
            if (l[0] == ""):
                self.help_peinfo()
            else:
                id, size = get_id_size(line)
                response, size = CTCore.get_response_and_size(id, "all")
                name = CTCore.get_name(id)

                self.retval = "Displaying PE info of object {} ({}) [{} bytes]:".format(id, name, size)
                if len(l) > 1 and l[1].lower() == "-p":
                    self.retval += "Checking for packers..."
                    pescan = PEScanner(response, '', peid_sigs="userdb.txt")
                else:
                    pescan = PEScanner(response, '', '')

                out = pescan.collect()
                self.retval += '\n'.join(out)
        except Exception,e:
            self.retval = str(e)

    def help_peinfo(self):
        self.retval = newLine + "Display PE info of the file"
        self.retval += newLine + "Usage: peinfo <obj_id> [-p]" + newLine
        self.retval += "OPTIONS:"
        self.retval += "     -p     -   Check for packers"

    def do_find(self,line):
        try:
            line = str(line)
            l = line.split(" ")
            if len(l) < 2:
                self.help_find()
            else:
                pattern = " ".join(l[1:])
                if l[0].lower() == "all":
                    self.retval = "Searching '{}' in all objects:".format(pattern)
                    for i in range(0,len(CTCore.objects)):
                        response, size = CTCore.get_response_and_size(i, "all")
                        name = CTCore.get_name(i)

                        search_res = find_pattern(response, pattern)
                        if len(search_res) > 0:
                            self.retval += newLine + " {} [{}]:".format(name,str(i))
                            for res in search_res:
                                self.retval += "   " + res
                    self.retval += newLine
                else:
                    id, size = get_id_size(line)
                    response, size = CTCore.get_response_and_size(id, "all")
                    name = CTCore.get_name(id)

                    self.retval = "Searching '{}' in object {} ({}):".format(pattern, id, name)
                    self.retval += newLine

                    search_res = find_pattern(response, pattern)
                    if len(search_res) > 0:
                        for res in search_res:
                            self.retval += res
                    else:
                        self.retval += "     No Results found"
                    self.retval += newLine
        except Exception,e:
            self.retval = str(e)

    def help_find(self):
        self.retval = newLine + "Search for a regular expression in all or specific object"
        self.retval += newLine + "Usage: find <obj_id / all> <pattern>" + newLine
        self.retval += newLine + "Output data is displayed as follows:"
        self.retval += newLine + "   ([Line number] , [Offset from begining of file]) : [Found string]" + newLine

    def do_slice(self,line):
        try:
            line = str(line)
            l = line.split(" ")
            if len(l) < 3:
                self.help_slice()
            else:
                id, size = get_id_size(line)
                response, size = CTCore.get_response_and_size(id, "all")
                name = CTCore.get_name(id)
                offset = int(l[1])
                length = l[2]
                bytes, length = get_bytes(response,offset,length)

                self.retval = "Displaying {} of bytes from offset {} in object {} ({}):".format(length, offset, id, name)
                self.retval += newLine
                self.retval += bytes
                self.retval += newLine
        except Exception,e:
            self.retval += str(e)

    def help_slice(self):
        self.retval = newLine + "Returns bytes from offset in given length"
        self.retval += newLine + "Usage: slice <obj_id> <offset> <len | 'eob'>" + newLine

    def do_req(self, line):
        try:
            line = str(line)
            l = line.split(" ")
            if (l[0] == ""):
                self.help_req()
            else:
                id, size = get_id_size(line)
                request, size = CTCore.get_request_size(id, "all")
                name = CTCore.get_name(id)
                self.retval += "Displaying request for object {} ({}) [{} bytes]:".format(id, name, size)
                CTCore.show_errors()
                self.retval += newLine + request
        except Exception,e:
            self.retval += str(e)

    def help_req(self):
        self.retval = newLine + "Prints full request of object"
        self.retval += newLine + "Usage: req <obj_id>"

    def do_jsbeautify(self,line):
        try:
            line = str(line)
            import jsbeautifier
            l = line.split(" ")
            if len(l) < 2:
                self.help_jsbeautify()
            else:
                OPTIONS = ['slice','obj']
                option = l[0]

                if option not in OPTIONS:
                    self.retval = "Invalid option"
                    return False

                id = l[1]
                response, size = CTCore.get_response_and_size(id, "all")
                name = CTCore.get_name(id)

                if option == "slice":
                    offset = int(l[2])
                    length = l[3]

                    bytes, length = get_bytes(response,offset,length)
                    js_bytes = bytes
                    res = jsbeautifier.beautify(js_bytes)
                    self.retval = res

                if option == "obj":
                    res = jsbeautifier.beautify(response)
                    obj_num = CTCore.add_object("jsbeautify",res,id=id)
                    self.retval = " JavaScript Beautify of object {} ({}) successful!".format(str(id), name)
                    self.retval += " New object created: {}".format(obj_num) + newLine

        except Exception,e:
            self.retval = str(e)

    def help_jsbeautify(self):
        self.retval = newLine + "Display JavaScript code after beautify"
        self.retval += newLine + "Usage: jsbeautify <obj / slice> <object_id> <offset> <length>"
        self.retval += newLine + "Example: jsbeautify slice <object_id> <offset> <len | eob>"
        self.retval += newLine + "Example: jsbeautify obj <object_id>"

    def do_strings(self, line):
        try:
            line = str(line)
            l = line.split(" ")
            if (l[0] == ""):
                self.help_strings()
            else:
                id, size = get_id_size(line)
                response, size = CTCore.get_response_and_size(id, "all")
                name = CTCore.get_name(id)

                self.retval = "Strings found in object {} ({}) [{} bytes]:".format(id, name, size)
                strings = CTCore.get_strings(response)
                self.retval += (newLine.join(str for str in strings))
        except Exception,e:
            self.retval = str(e)


    def help_strings(self):
        self.retval = newLine + "Display strings found in object"
        self.retval += "usage: strings <obj_id>"

    # Short for plugin
    def do_p(self,line):
        self.do_plugin(line)

    def help_p(self):
        self.help_plugin()

    def do_plugin(self, line):
        try:
            line = str(line)
            l = line.split(" ")
            if (l[0] == ""):
                self.help_plugin()
            elif (l[0] == "-l"):
                self.retval = "Loaded Plugins ({}):".format(len(CTCore.plugins))
                for plug in CTCore.plugins:
                    self.retval += " {} : {} - {}".format(plug.id, plug.name, plug.description)
                self.retval += newLine
            else:
                if (l[0].isdigit() and int(l[0]) < len(CTCore.plugins)):
                    plugin_name = CTCore.plugins[int(l[0])].name
                else:
                    plugin_name = l[0]
                plugin_args = l[1:]
                result = CTCore.run_plugin(plugin_name, plugin_args)
                if result is not None:
                    self.retval = result
        except Exception,e:
            self.retval = str(e)

    def complete_plugin(self, text, line, begidx, endidx):
        if not text:
            completions = CTCore.plugins.keys()[:]
        else:
            completions = [ f
                            for f in CTCore.plugins.keys()
                            if f.startswith(text)
                            ]
        return completions

    def help_plugin(self):
        self.retval = "Launching an external plugin (alias: p)" + newLine
        self.retval += "usage: plugin <plugin_name / plugin_id> [-l] <*args>"
        self.retval += "     -l      - List all available plugins" + newLine
        self.retval += "examples:"
        self.retval += "     plugin find_scripts"
        self.retval += "     plugin 1"
        self.retval += "     p find_scripts"

    def do_about(self, line):
        self.retval = CTCore.ABOUT

    def help_about(self):
        self.retval = newLine + "Prints about information"

    def help_exit(self):
        self.retval = 'Exits from the console'
        self.retval +=  'Usage: exit'
