```THESE NOTES ARE DERIVED FROM TRYHACKME```
# Brim
 - use it for looking at pcap, it can match in suricata rules, so might make it easier to detect malicious traffic. Zeek can load pcap faster though.
 - Download link https://www.brimdata.io 
 - `_path=conn` view conneciton types. You can replace with `dns`, `http`.
 - Pipe it to toher stuffs like `_path=dns | count() by query`  query is a field name. This will list different packets with field names
 - `filename!=null` see file activity
 - `event_type==alert` to see suricata alerts
 - `mime_type=image/gif`
 - `_path=="conn" | cut id.orig_h, id.resp_p, id.resp_h,geo | sort | uniq`  cut can be used to get only the required fieldnames. sort and uniq to get unique values count
 - `_path=="conn" | cut id.orig_h, id.resp_p, id.resp_h,geo.orig, geo.resp.region | sort | uniq | geo.resp.region !=null` access recursive fields like this
 - `192 and NTP` logical AND supports OR as well
 - `id.orig_h==192.168.121.40`
 - `_path=="conn" | cut id.orig_h, id.resp_h | sort | uniq -c | sort -r` to see frequest communication
 - `_path=="conn" | cut id.orig_h, id.resp_p, id.resp_h, duration | sort -r duration` long duration of communications
 - `event_type=="alert" | cut alert.category, alert.metadata.mitre_technique_name, alert.metadata.mitre_technique_id, alert.metadata.mitre_tactic_name | sort | uniq -c` see mitre metadata stuffs

# zeek
 - formerly brim
 - indepth logging and monitoring
 - has own scripting functionality
 - https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/b94f413787763b1bdefe17c4bfb29782.png
 - `zeekctl start` service mode for network monitoring
 - To read pcap `zeek -C -r sample.pcap `
 - To see specific column we can use zeek-cut `cat conn.log | zeek-cut uid proto id.orig_h id.orig_p id.resp_h id.resp_p`. Another simple example `cat conn.log | zeek-cut duration`
 - To remove duplicate values `sort | uniq`.
 - And count as well `sort | uniq -c `.
 - Sort numerically `sort -n` add -r, or do `-nr` to do reverse sorting.
 - If you do not know the field name, we can use `-f` example `cut -f 1` to get the first field.
 - Zeek signature are sort of like a conditions. it has its own scripting language. 
 - Zeek signatures have three parts `Signature id` its just a unique signature name , `Conditions` header or conent and `Action`.
 - Possible `Header` values `src-ip: Source IP.
dst-ip: Destination IP.
src-port: Source port.
dst-port: Destination port.
ip-proto: Target protocol. Supported protocols; TCP, UDP, ICMP, ICMP6, IP, IP6`
 - Possible Content value `payload: Packet payload.
http-request: Decoded HTTP requests.
http-request-header: Client-side HTTP headers.
http-request-body: Client-side HTTP request bodys.
http-reply-header: Server-side HTTP headers.
http-reply-body: Server-side HTTP request bodys.
ftp: Command line input of FTP sessions.`
 - Context	`same-ip: Filtering the source and destination addresses for duplication.`
 - Action	`event: Signature match message.`
 - Comparison Operators	`==, !=, <, <=, >, >=`
 - To use signature on pcap `zeek -C -r sample.pcap -s sample.sig`
 - Sample signature `signature http-password {
     ip-proto == tcp
     dst_port == 80
     payload /.*password.*/
     event "Cleartext Password Found!"
}

signature: Signature name.
ip-proto: Filtering TCP connection.
dst-port: Filtering destination port 80.
payload: Filtering the "password" phrase.
event: Signature match message.`
 - It has its scripting language, its event-driven not packet driven
 - To learn `https://try.bro.org/#/?example=hello`
 - Extension is .zeek
 - Sample derived from tryhackme `event dhcp_message (c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
{
print options$host_name;
}`
 - `c: connection` has the entier packet, and you can dump it as `print c;`
 - Access fields this way `print fmt ("Source Host: %s # %s --->", c$id$orig_h, c$id$orig_p);`.
 - zeek_init() and zeek_done() are two events that will always occur, one when zeek start, the other when it terminates.`event zeek_init()
	{
	print "Hello, World!";
	}

event zeek_done()
	{
	print "Goodbye, World!";
	}
`
 - To load script `@load misc/dump-events`
 - To use specific zeek scripts `zeek -C -r smallFlows.pcap dhcp-hostname.zeek `
 - A command I used that helped `cat dns.log | zeek-cut query | sort | uniq | grep -v -e '*' -e '-' | wc -l`
 - Base scripts location `/opt/zeek/share/zeek/base`
 - You can load all of them via `zeek -C -r sample.pcap local`
 - Load specific via `zeek -C -r sample.pcap /opt/zeek/share/zeek/policy/protocols/ftp/detect-bruteforcing.zeek`
 
# SNORT
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
