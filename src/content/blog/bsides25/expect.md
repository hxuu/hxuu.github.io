---
title: "\"Bsides 2k25\": Abusing an Overflow to Trigger Command Injection in Expect"
date: 2025-12-22T02:22:05+01:00
tags: ["ctf", "write-up", "bsides"]
image: ./background2.png
author: "hxuu"
description: "I discuss how shared TLS certificates across unrelated domains can lead to SOP abuse when one domain can present itself as another domain using SXGs"
---

## Notes (before writing)

1. Two Features: http/2 server pushed and signed http exchanges introduce vulnerabilities
that affect the same origin policy.
2. The reason for these vulnerabilities is the mismatch between authority check.
3. Authority over a given connection is given to any uri inside the SAN list in a TLS
certificate. Authority here means I can contact the server using the other origins already existing connection.
4. Signed http exchanges enable publishers to package their content and make OTHER
parties distribute it for them (like cdn). The latter could specify which origin this is for


## Introduction

This blog post details my design process for a "hard" CTF challenge for Cybear's CTF
which exploited a mismatch in the notion of authority in the context of same-origin policy
across HTTP/2 server pushes and cross SXGs.
