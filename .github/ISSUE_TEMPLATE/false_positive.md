---
name: Report a false positive
about: The detector flagged a legitimate message as a scam
title: "[False positive] "
labels: false-positive
assignees: ''
---

## The message

Paste the text or a screenshot here:

```
[PASTE HERE]
```

## What the detector said

Run this and paste the output:

```bash
PYTHONPATH=. python -m scam_shield analyze "[YOUR MESSAGE]"
```

## What it should have said

What verdict and scam type do you think was correct? (clean / suspicious /
likely_scam / scam) and why?

## Context

What kind of message was this? (legitimate business email, real bank
notification, marketing SMS, government notice, etc.)
