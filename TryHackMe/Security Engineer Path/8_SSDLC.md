# Secure SDLC
- Understand security posture first.
- gap analysis
- <!--StartFragment-->

Create **Software Security Initiatives** (SSI) by establishing realistic and achievable goals with defined metrics for success

<!--EndFragment-->
- Formalise process.
- Invest in security trainnig.

# The process
- risk assessment, threat modelling, coding/scanning review, security assessment, VAPT.

# 1. Risk Assessment
- Calculating the likelyhood of a vulnerability being exploited by an attacker and its impact.
- Qualitative: risk=severity x likelyhood, L,M,H.
- QUantitatuve: attaches numerical value.

# 2. Threat Modeling
- Identify potential risk, better done in design phase.

### STRIDE
- Spoofing, tampering, repudiation, information disclosure, denial of services and escalation of privilege. Built on top of CIA.
- Design data low, identify nodes, and think how can an attacker achieve each points in STRIDE.

### DREAD
- <!--StartFragment-->

Damage Potential, Reproducibility, Exploitability, Affected Users and Discoverability

<!--EndFragment-->
- Can be used to determine risk.

### PASTA
- Process for Attack Simulation and Threat Analysis
- It has steps, just google it.

# 3. Secure Coding
- SAST. Used Graudit and sonarqube with GOSEC in the past. list https://github.com/analysis-tools-dev/static-analysis
- DAST, OWASP ZAP (u know about these).
- IAST (interactive application security testing).
- Checks source code like SAST, but in post built stage, agents that sends query to app.
- RASP (Runtime Application Self Protection) another app that analysises traffic on the main app.

# 4. Security Assessment
- VAPT (During maintance and operation phase)

# SSDLC methodolgies
- Microsofts SDL, OWASPS sdlc