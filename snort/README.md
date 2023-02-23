## RULES
 - Detect png `alert tcp any any <> any any  (msg: "PNG Packet Found";content:"|89 50 4E 47|"; ;sid: 100001; rev:1;)` -> any source any port <> (bidirectional), content could be string "||" mean hex byte
 - snort -c local.rules -r ftp-png-gif.pcap -l .
 - `snort -r snort.log.1677011936 -vv -d`  -r (read from this log file) -d (dump the packets as well)
 - More stuffs in https://asecuritysite.com/forensics/snort?fname=with_pdf.pcap&rulesname=rulessig.rules
 - for torrent files `alert tcp any any <> any any (msg:"torrent"; content:".torrent";sid:100001;)`
 - `sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A console` To run in IPS mode
 - `snort -i eth0 -v`
 - For tryhackme brute force challange my alert rule was `alert tcp any any -> any 22 (msg:"SSH Brute-Force attack"; detection_filter:track by_src, count 100, seconds 20; sid:1000281; rev:2;)`
 
## Interensting links
 - https://securitylab.disi.unitn.it/lib/exe/fetch.php?media=teaching:netsec:2016:slides:t11:group2_-_ids_snort.pdf
 
