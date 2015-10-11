##CapTipper v0.3

[Logo]: http://4.bp.blogspot.com/-uuRE1KkS5Jo/Vb8j-cfEuHI/AAAAAAAAeY4/MltsTu7jG5E/s1600/CapTipper_logo.png
![Logo]

Fork of https://github.com/omriher/CapTipper
Original documentation: http://captipper.readthedocs.org

CapTipper is a python tool to analyze, explore and revive HTTP malicious traffic.  

This is a fork of CapTipper that uses the Python interactive console instead of CTConsole.
Some new features are included. Some are overlapping with the features of the current CapTipper version as the code of this fork is based on an earlier version.

```>>> help
This is a normal Python shell with some special commands for your convenience.

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

jseval(x)            run conversation x through JS evaluation

_help                Normal python help
```

The jseval command requires installing Thugdom, a fork of Thug (https://github.com/execgit/thugdom).
The IDS command set requires a version of Snort (https://www.snort.org/) as well as a ruleset to match packets against.

***
###Original Info

Written By Omri Herscovici

Please open an issue for bugs.  
I would be happy to accept suggestions and feedback to my mail :)  

CapTipper: http://www.omriher.com/2015/01/captipper-malicious-http-traffic.html  
Email: [omriher@gmail.com](mailto:omriher@gmail.com?Subject=CapTipper feedback)  
Twitter: [@omriher](https://twitter.com/omriher)




