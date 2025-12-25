---
title: "\"Bsides 2k25\": Popping XSS Through Cache Poisoning & Escalating to RCE"
date: 2025-12-22T01:09:45+01:00
tags: ["ctf", "write-up", "bsides"]
image: ./background1.png
author: "hxuu"
description: "I explore a misaligned trust chain between a CDN, a Tornado web app, and an admin bot that allows cache poisoning via a GET request body.\nThis lets us serve an XSS payload to the admin. We then abuse environment variables injection to get RCE"
---

## TL;DR

A misaligned trust chain between a CDN, a Tornado web app, and an admin bot allow cache poisoning via a GET request body. This lets us serve an XSS payload to the admin despite the bot visiting a “safe” URL.

With admin access, we abuse a dotenv configuration writer to inject environment variables, then execute a Python subprocess under a poisoned environment to gain RCE and read `/flag.txt`.

## Challenge Overview

* CTF: BSides Algeirs 2025
* Challenge: Library Vault
* Category: Web
* Points: 500 (1 solve, kudos to my friend Fodhil for solving it!!)
* Description: Our librarian is very mature, well-read, and believes that antigravity is the way—reading books to go up in life.
* Author: [keystone](https://discord.com/users/699651457242365952)
* Attachments:
    * [library_vault.zip](https://github.com/Shellmates/BSides-Algiers-2025-challenges/blob/main/web/LibraryVault/LibraryVault_Redacted.zip)

![challenge description](/images/2025-12-25-18-04-08.png)


---

### Context & First Impressions

At first glance, this didn’t look like a “single bug” challenge. There’s a CDN in Go, a Tornado app, Redis, and an admin bot,
and with my friend solving it after a 10 hour grind, it already tells me the exploit probably lives between components,
not inside one function.

```bash
bsides25/library-vault/LibraryVault
➜ tree -L 1
.
├── build-docker.sh
├── cdn-service
├── Dockerfile
├── flag.txt
├── redis
├── supervisord.conf
└── web-app
```

The best way to inspect the code is by interacting with the UI first.

-- do video highlighting search functionality

We start with a web application that has a search functionality and ability to "report"
a URL to an admin bot. Without even checking the source, we test for XSS which pops,
locally sending a request, but reporting the page to the admin bot doesn't trigger the XSS.

This mismatch in behavior means that something is blocking our XSS in the admin bot:

1. Either the bot isn't seeing my input, or
2. The response it gets is not the one I think it is

Instead of brute-forcing payloads, we stop and look at *how requests flow.*

---

Just like we did previously to get a feeling for the code base, we'll do the same, one level
deeper to understand how components flow among each other. This saves time to analyze only relevant code,
and gives a general overview of the system.

```bash
bsides25/library-vault/LibraryVault
➜ tree -L 2
.
├── build-docker.sh
├── cdn-service
│   ├── go.mod
│   └── main.go
├── Dockerfile
├── flag.txt
├── redis
│   ├── redis.conf
│   └── redis_init.sh
├── supervisord.conf
└── web-app
    ├── app.py
    ├── config.py
    ├── db
    ├── handlers
    ├── requirements.txt
    ├── static
    ├── templates
    └── utils

9 directories, 11 files
```

We have 3 components:

1. cdn-service: This is the front facing service that we interact with.
2. web-app: This is the actual web application handling backend logic
3. redis: A storage medium we'll get to understand shortly after.

The relevant code in cdn-service is this:

```go
func cdnHandler(w http.ResponseWriter, req *http.Request) {
    var res string
    var err error
    if dynamic(req) {
        w.Header().Set("X-Cache", "dynamic")
        res, err = forwardRequest(req)
        if err != nil {
            http.Error(w, "Failed to fetch from origin: "+err.Error(), http.StatusBadGateway)
            return
        }
    } else {
        // Cacheable GET request
        key := hash(req.URL.String())
        res, err = rdb.Get(ctx, key).Result()
        if err == redis.Nil {
            // Cache miss, fetch from origin
            w.Header().Set("X-Cache", "miss")
            res, err = forwardRequest(req)
            if err != nil {...}
        } else if err != nil { ... } else {
            // Cache hit
            w.Header().Set("X-Cache", "hit")
        }

        // Store the response in Redis with a 60-second expiration
        err = rdb.SetNX(ctx, key, res, 60*time.Second).Err()
        if err != nil { ... }
    }
    // send response...
}
```

The CDN is a simple caching server. It checks our request if dynamic (POST request or GET to /panel),
if so, it forwards it to the web app, else it caches the response using Redis as the storage medium.

What catches my eye is how the key is calculated: The full (denormalized) path
is used as a cache key. I usually expect caching servers to use more than URLs as cache
keys, like headers and whatnot. This one though doesn't, let's note that.

Another interesting observation is the discrepancy between cache keys and forwarded URL.
When the server received a GET to `/search/../search?query=FOO`, it cached the latter, but sends
a reuqest to `/search?query=FOO`. This didn't prove to be useful in the easy variation, but maybe the revenge uses this idea. I'm noting it anyways.

---

What I'm most interested in is why our XSS payload which works locally, doesn't work
in the bot context, let's check the latter code to understand what happens:

```py
class ReportHandler(BaseHandler):

    async def post(self):
        url = f'http://127.0.0.1:1337/search?query={quote("I BELEIVE IT DOESNT WORK")}'
        threading.Thread(target=run_bot, args=(url,)).start()
        self.write({"status": "success", "message": "Thanks for your report! We will review it shortly."})
```

As we can see, the bot visits a "safe" URL. If the query isn't an XSS payload, then it doesn't pop, as simple as that.

This confirms my hunch: the response the admin gets is not the one I thought it was.

---

Before we carry on, and since this is a CTF challenge, we have to locate the flag. It's in `/flag.txt`.
No sink was found in the code base (LFI gadgets...etc), so our only way is to get RCE (in other context, RCE is the goal anyways haha).

Normal user routes are benign too, so our only choice is to follow the XSS route to take over the admin's account and move from there.

### Threat Model

Taking a step back, let's revisit what I have:

1. I’m unauthenticated.
2. I can hit the CDN.
3. The admin bot is internal and only visits a fixed URL.
4. Redis sits in the middle.
5. The flag is on disk.

So the only realistic path is:

**me → influence something cached → admin loads it → pivot → RCE**

Anything else (direct file read, direct command exec) would be too easy and clearly not intended.

### Exploration & Failed Paths

I spent some time trying to fight the bot logic directly.

The report handler hardcodes the URL:

```bash
/search?query=I BELEIVE IT DOESNT WORK
```

No reflection. No user input. Dead end.

That basically kills all classic “send admin my link” ideas.

So the question became:
> if I can’t control where the admin goes, can I control what is served there?

If we go back to notes though, we remember the cache key:

```go
key := hash(req.URL.String())
```

The cache key is **only the URL string.**

At the same time, if we track the code of the /search endpoint, we notice the following:

```py
class SearchHandler(BaseHandler):
    async def get(self):
        query = self.get_argument("query", default=None)

        await insert_search(query)

        # irrelevant stuff here...
        self.render("search.html", search = query, verified_only=verified_only, results=results)
```

`SearchHandler` extends `BaseHandler`, and `BaseHandler` extends `tornado.web.RequestHandler`

![both query and body parameters are considered image](/images/2025-12-25-22-56-00.png)

Tornado’s get_argument() doesn’t really care where a parameter comes from. Query string, body -> same thing. If both
are present, an array [queryString, bodyParam] is created, and the last element (body param) is chosen to be the query.

What does this mean for us? Well, it creates a disagreement:

* CDN: “GET requests are keyed by URL, body doesn’t matter”
* Tornado: “If there’s a body, I’ll read it anyway”

That means I can do something cursed but valid:

* Send a GET request to the exact URL the admin will visit
* Put my payload in the request body while having the query string "safe"
* CDN caches the response under the safe URL
* Admin later gets my response

That’s the exploit. Everything else is just plumbing.

### We got admin, now what?

Getting admin access feels great~ but it's checkpoint, not our finish line.

A good question to ask ourselves now is what has changed in the system now that I’m admin?

The answer is: **new routes unlocked**.

Digging around the UI, the only new surface that appears is /panel.

![checking /panel](/images/Peek\ 2025-12-25\ 23-10.mp4)

If we check the code, two actions stand out immediately:

1. update_config

```py
ENVIRON_FILE = '.env'

class PanelHandler(BaseHandler):

    @tornado.web.authenticated
    async def post(self):
        if not self.is_admin():
            self.set_status(403)
            self.render("error.html", error="You are not authorized to access this page.")
            return

        action = self.get_argument("action", default="")

        if action == "update_config":
            backup_server = self.get_argument("backup_server", default="")
            archive_path = self.get_argument("archive_path", default="")

            if not backup_server or not archive_path:
                self.render("panel.html", error="Missing configuration parameters", result="",
                           backup_server=backup_server, archive_path=archive_path)
                return


            try:
                set_key(ENVIRON_FILE, "BACKUP_SERVER", backup_server)
                set_key(ENVIRON_FILE, "ARCHIVE_PATH", archive_path)

                load_dotenv(ENVIRON_FILE, override=True)
                return
            except Exception as e:
                # something...
```

2. run_backup

```python
        if action == "run_backup":
            load_dotenv(ENVIRON_FILE)
            backup_server = os.getenv("BACKUP_SERVER", "")
            archive_path = os.getenv("ARCHIVE_PATH", "")

            # Prepare environment variables for the subprocess
            env = os.environ.copy()
            env["BACKUP_SERVER"] = backup_server
            env["ARCHIVE_PATH"] = archive_path

            # Execute backup script with environment variables loaded
            try:
                result = subprocess.run(
                    ["/usr/local/bin/python3", "/app/utils/backup_catalog.py"],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                output = result.stdout if result.returncode == 0 else result.stderr
                self.render("panel.html", error=None, result=output, backup_server=backup_server, archive_path=archive_path)
            except Exception as e:
                # something...
```

Here’s what we have:

* As admin, I can write arbitrary values into .env
* Those values are loaded into the process environment
* A Python interpreter is then launched with those variables

At this point, blood rushed through my vains as I picture the flag in the backup_catalog vulnerability, to my luck though:

```python
#!/usr/bin/env python3
import os
import time

def backup():
    backup_server = os.getenv("BACKUP_SERVER", "localhost")
    archive_path = os.getenv("ARCHIVE_PATH", "/tmp/backup")

    print(f"Starting catalog backup process...")
    print(f"Configuration: SERVER={backup_server}, PATH={archive_path}")

    # Simulate backup process
    print("Connecting to backup server...")
    print("Connection established.")
    print(f"Compressing catalog data to {archive_path}...")
    print("Uploading archive...")
    print("Backup completed successfully.")

if __name__ == "__main__":
    backup()
```

![it was special](https://media1.giphy.com/media/v1.Y2lkPTc5MGI3NjExYnI0aXlsejhqYTQ2cDU5cHE0NHlld2pycjlzZnU4NW5weDh5emNldSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/rvxMJNyHAgwlW4YWpJ/giphy.gif)

It was special..ly empty.

No os.system, no subprocess, no eval, no file access.
The script is boring by design.

This is an important moment, because it tells us something subtle:

> The vulnerability is not in what the script does,
> but in the fact that Python is being executed at all.

The attack surface here is not the backup logic.
It’s the Python interpreter startup with attacker-controlled environment variables.

So the question changes again.

Not:
> “How do I exploit the backup script?”

But:
> “What does Python do before it even reaches my code?”

This is where environment variables stop being configuration, and start being control

### Exploiting environment variables to achieve RCE

![Google search about exploiting environment variables](/images/2025-12-25-23-20-51.png)

A simple google search reveals this article about the topic: https://www.elttam.com/blog/env/

---

Give the article a read, I don't intend on re-explaining the vulnreability here, but here's a quick recap so we’re on the same page:

* Python’s interpreter behavior can be influenced by environment variables.
* `PYTHONWARNINGS` allows loading a module during interpreter startup.
* If we can control which module is loaded, and that module does something dangerous using other environment variables, we get code execution before our script even runs.

That’s the punchline.

What I’m interested in doing with this writeup, though, is not just repeating the blog, but giving the perspective of a security researcher (a beginner one, I might add xD) on how we could have reasonably discovered this ourselves instead of relying on external sources.

### Putting the reseracher hat: finding the vuln ourselves

Let’s first separate what is given from what still feels like a magic jump.

Up to and including `PYTHONWARNINGS`, the article makes total sense.
First, the part up to and including PYTHONWARNINGS is clear. The article thought of how
the interpreter could be made vulnearble, read its man page and found a the warning control system.
In its code, it found the arbitrary module load.

The question I will answer is:
> How can we systematically find the target module that yields RCE?

My approach will help clear the "magic jump" in the article.

---

I start every research with a mental model that highlights where I stand and what my question is.
In this case, I know I want to exploit python using environment variables, and from the blog,
I know `PYTHONWARNINGS` allows me to load a module. However, which one should I choose?

The question is better formed in another way:

* Which python module makes malicious use of environment variables? And how to track this sink to find a suitable source?

Let's first grep for os.environ.get( and similar things, we get a list of everything
BROWSER stands out, let's see in which file, webbrowser, interesting, let's check the docs,
docs says we can specify a BROWSER to run, i.e a binary!

webbrowser only defined the prototype (JS reference lol), it doesn't execute anything,
let's see where webbrowser is used and whether it's used by modules that trigger it directly.

grep for import webbrowser and such, we find guess what! antigravity!

---

After we found antigravity, we carry on with the exploit and whatnot to get the flag.

and in the spirit of htb, let's do a reverse shell just for fun!

PWNED!!!!

