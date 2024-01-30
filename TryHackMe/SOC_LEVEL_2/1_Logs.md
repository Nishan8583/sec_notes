# Logs
- Helps answer question what, when, where, who, were they successfull, what.
- Log types: application, audit, security, …
- Format: unstructured, structure, semistructured.

# Rsyslog
- /etc/rsyslog.d/98-websrv-02-sshd.conf
- Log Management: storage, organization, backup, review.
- Example config
<!--StartFragment-->

```yaml
$FileCreateMode 0644
:programname, isequal, "sshd" /var/log/websrv-02/rsyslog_sshd.log
```

<!--EndFragment-->

# Log levels
- security, operational, legal, debug