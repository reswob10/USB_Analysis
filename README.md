# USB_Analysis
This script allows you to check what USB Devices have been plugged into a Windows PC by checking the registry for new and updated keys


C:\Tools\USB_script>python USB_analysis.py -h

usage: USB_analysis.py [-h] [-V VLEVEL] [-d HISTORY] [-sb BBS]


Options to run.


optional arguments:

  -h, --help  show this help message and exit
  
  -V VLEVEL   Level of verbosity: 0 - None, 1 - Minimum, 2 - Maximum
  
  -d HISTORY  On each suspected machine, how far in the past do you want to
              search? (# days)
              
  -sb BBS     If a permitted device is found, skip analysis AND do not log : y
              - Skip/Do NOT log if found, n - Do NOT skip/Log if found
