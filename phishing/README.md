# Sender Policy Framework (SPF)
- SPF records have which include list of mail servers that can send mail on behalf of the domain
- Ex from tryhacke `v=spf1 ip4:127.0.0.1 include:_spf.google.com -all`. Here ip `127.0.0.1` and domain `_spf.google.com` can send mail. `-all` means non auhorized mail will be rejected.
- `https://dmarcian.com` is popularly used for SPF informaiton.
- Be wary of `SPF failed` in tools like `https://toolbox.googleapps.com/apps/messageheader/`
- Reference to SPF syntax: `https://dmarcian.com/spf-syntax-table/`

## DomainKeys Identified Mail (DKIM) similart to SPF but exists in SPF
- `a tamper-evident domain seal associated with a piece of email`
- Result will be under `Authentication-Results` head `dkim=pass`
- `https://dmarcian.com/domain-checker/` check domain DMARC info here

## Domain-based  Message Authentication Reporting, & Conformance (DMARC)
- Combines DKIM and SPF
- DMARC record example `v=DMARC1; p=quarantine; rua=mailto:postmaster@website.com`. if check fails `quarantine` send reports to `postmaster@website.com`.

## S/MIME Secure/Multipurpose internet Mail Extensions
- Similar to Digital signature
- Sender should have a digital certificate, receiver should have senders public key to verify.
# Email Analysis
- guide in https://mediatemple.net/community/products/all/204643950/understanding-an-email-header
- Upload eml file to https://app.phishtool.com
- `Sender` and `Reply-To` not same is sus
- View source code in email code, might give you some extra info
- SUS: senders detail and senders email address is different something like this `spooed@address.com<some_random_@address.com>`
- SUS: shorten urls
- SUS: If u are the BCC
- SUS: urgency
- view raw HTML
- Tools for email head analysis only:
  - https://toolbox.googleapps.com/apps/messageheader/analyzeheader
  - https://mha.azurewebsites.net
  - https://mailheader.org
- Extract URLs
  - https://www.convertcsv.com/url-extractor.htm
  - https://gchq.github.io/CyberChef/ (use the extract URLs tool)
- Open email in sandbox
  - https://www.hybrid-analysis.com/
  - https://www.joesecurity.org/
  - https://app.any.run
- Atuomated
  - https://www.phishtool.com (use this often)

## References
- https://www.incidentresponse.org/playbooks/phishing

