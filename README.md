# evtxtolog
Parses evtx-files to simple log-files readable by most common tools. This is accomplished using the python-evtx tool from https://github.com/williballenthin/python-evtx, the Event-ID-List based on https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx and some parsing.

## Usage
```
$ python3 evtxtolog.py --help                    
usage: evtxtolog.py [-h] evtx_file output_file

positional arguments:
  evtx_file
  output_file

optional arguments:
  -h, --help   show this help message and exit
```

## What it this good for?
Now you can skim over the contents of an .evtx-File from within Linux using for example https://lnav.org/.
