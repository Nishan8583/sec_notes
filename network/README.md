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
