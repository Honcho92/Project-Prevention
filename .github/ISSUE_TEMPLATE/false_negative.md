---
name: Report a false negative
about: The detector missed a real scam
title: "[False negative] "
labels: false-negative
assignees: ''
---

## The message

Paste the text or a screenshot here. **Redact any personal information**
(phone numbers, email addresses, your name) before posting.

```
[PASTE HERE, REDACTED]
```

## What the detector said

Run this and paste the output:

```bash
PYTHONPATH=. python -m scam_shield analyze "[YOUR MESSAGE]"
```

## Why you know it's a scam

What signals told you this was a scam? (the brand being impersonated, the
money ask, the urgency language, etc.)

## What it should have caught

What verdict and scam type do you think was correct?
