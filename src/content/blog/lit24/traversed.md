---
title: "\"LITCTF 2k24\": Reading Arbitrary Files via URL-Encoded Path Traversal"
date: 2024-08-13T19:05:10+01:00
tags: ["ctf", "write-up", 'litctf']
author: "hxuu"
showToc: true
TocOpen: false
draft: false
hidemeta: false
comments: false
description: "I bypass dot-blocking by URL-encoding path separators, then use /proc/self/cwd to resolve the working directory and read the flag file directly."
canonicalURL: ""
disableHLJS: false
disableShare: false
hideSummary: false
ShowReadingTime: true
ShowBreadCrumbs: true
ShowPostNavLinks: true
ShowRssButtonInSectionTermList: true
UseHugoToc: true
editPost:
    URL: "https://github.com/hxuu/content"
    Text: "Suggest Changes"
    appendFilePath: true
---

## Challenge Description

```
name: traversed
category: web
points: 123
```

I made this website! you can't see anything else though... right?? URL: http://litctf.org:31778/

## Solution

Based on the name of the challenge, I can feel a path traversal vulnerability looming around
lol, anyway, let's check the website:

![initial](/images/2024-08-13-19-11-40.png)

As we can see, nothing is in the page, the hint though lies within the url bar,
let's check if can traverse the the filesystem and reveal the contents of `/etc/passwd`.

![trying-to-use-browser](/images/2024-08-13-19-13-28.png)

We got nothing, but that's only because we used a dot, The server might be configured to decode URL-encoded paths before processing them,
so let's try again, with the url-encded version of `.` that is `%2e`.

![got-etc-passwd](/images/2024-08-13-19-19-09.png)

Noice, we have arbitrary file read, we can also traverse the filesystem, but what we don't
have is the flag name and location. Guessing that the flag would be in the same directory
the current process is running at, and that the name well may be `flag.txt`. I used
the `/proc/self/cwd` which is a symbolic link that points to the current working directory
of the process accessing it, to extract the file `flag.txt` using something like this:

```bash
<traversing-up-the-file-system>/proc/self/cwd/flag.txt
```

![flag](/images/2024-08-13-19-47-52.png)

---

flag is: `LITCTF{backtr@ked_230fim0}`

Things learned from this challenge

* Path traversal with url encoded path
* use the /proc directory to get information about processes

