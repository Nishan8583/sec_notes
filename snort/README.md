## RULES
 - Detect png `alert tcp any any <> any any  (msg: "PNG Packet Found";content:"|89 50 4E 47|"; ;sid: 100001; rev:1;)` -> any source any port <> (bidirectional), content could be string "||" mean hex byte
 - snort -c local.rules -r ftp-png-gif.pcap -l .
 - `snort -r snort.log.1677011936 -vv -d`  -r (read from this log file) -d (dump the packets as well)
 - More stuffs in https://asecuritysite.com/forensics/snort?fname=with_pdf.pcap&rulesname=rulessig.rules
 - for torrent files `alert tcp any any <> any any (msg:"torrent"; content:".torrent";sid:100001;)`
