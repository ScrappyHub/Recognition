# Real-site smoke test and measurement sheet (v1.2.0)

Unit tests cannot cover the web engine. Run this once per release (about 20 minutes) and record results in the table at the bottom.
Use a normal tab unless stated. Shield level = Balanced, Tracking prevention = Balanced, unless stated.

## A. Does it break normal browsing? (item 2)
| # | Do this | Pass when |
|---|---|---|
| A1 | Open a news site, a video site, a webmail, a shopping checkout | Pages load, video plays, you can sign in and check out |
| A2 | Open the same pages with Shield level Strict | Still usable; note what breaks (expected: some canvas/audio sites) |
| A3 | Shield > site exception "off" for one site | Reload shows that site's trackers allowed, others still blocked |
| A4 | Ad-heavy page (a news site with banners) | Banners gone, no empty gaps larger than before, no missing article text |
| A5 | Shield > Test a URL: `https://doubleclick.net/x.js`, type Script | Blocked, rule shown |
| A6 | Click a link that opens a pop-up | Opens as a tab. A page that opens a window on load: blocked and Status says so |
| A7 | Private tab, click a pop-up link | Pop-up tab is also private |
| A8 | Click a `mailto:` link | Windows asks which mail app. A `ms-msdt:` link: blocked |

## B. Fingerprinting and ad blocking measured (item 3)
Record the same numbers for Recognition and for Brave (default shields) on the same machine.
| Site | What to record |
|---|---|
| coveryourtracks.eff.org | "Strong protection against tracking?" and fingerprint uniqueness (bits) |
| abrahamjuliot.github.io/creepjs | Trust score; whether canvas/audio/WebGL hashes change after you reload with a new session (restart the browser) |
| browserleaks.com/canvas, /webgl | Hash differs between two different sites in the same session (per-site noise) and is stable on reload of one site |
| d3ward.github.io/toolz/adblock.html | Percent of test domains blocked |
| adblock-tester.com | Score |
| Open any top-10 news site | Number of blocked requests (Shield page counter) and page load time versus Brave |
Expected honest result: lower than Brave on list breadth and cosmetic coverage until the lists are loaded; if the score is far lower after Update lists, file it as a bug with the site.

## C. Passkeys (item 1 of the original request)
| # | Do this | Pass when |
|---|---|---|
| C1 | Passkeys page > Run local test | Windows Hello prompt, then "signature verified" |
| C2 | passkeys.io or webauthn.io: register, sign out, sign in | Works with Windows Hello |
| C3 | Passkeys > block for one site, retry that site | The site reports passkeys not allowed; other sites unaffected |

## D. Full-page capture and PDF tools
| # | Do this | Pass when |
|---|---|---|
| D1 | Tools > Full-page PDF (A4) on a very long article | PDF opens, text readable, no cut line or missing strip at page joins |
| D2 | Full-page PDF (one long page) and Full-page PNG | Same content, correct width |
| D3 | A page with lazy-loaded images, scroll first and then capture | Note whether images below the fold appear (known limit if not) |
| D4 | Open a multi-page PDF, extract pages 2 to 3, save | New PDF has exactly those pages |

## E. Extensions (item 4)
| # | Do this | Pass when |
|---|---|---|
| E1 | Extensions > install `samples\extensions\hello-good` | Allowed; appears enabled after Restart |
| E2 | Install hello-review | Needs your approval; refused without it |
| E3 | Install a build with the `debugger` permission | Refused (deny) |
| E4 | Edit a file of an installed extension on disk, restart | Not loaded; Status says unapproved |
| E5 | Extensions > Test | Runs in a throw-away private tab; nothing persists |
| E6 | Try a real one: uBlock Origin Lite, Bitwarden, Dark Reader from the Chrome Web Store as unpacked or .crx | Record Works / Partly / Fails and why |

## F. Stress (item 6)
| # | Do this | Pass when |
|---|---|---|
| F1 | Open 30 tabs of mixed sites | No crash; memory stays reasonable; switching tabs responsive |
| F2 | Shield > Update lists with all four lists | Finishes; browsing stays responsive during and after |
| F3 | Add a 100,000-line custom list | Loads or is refused with a clear message |
| F4 | Kill the web engine process in Task Manager | Browser recovers or shows an error, does not hang |
| F5 | Full-page PDF of a 50,000 px page | Completes or refuses with a clear message |

## G. Install and update (items 5 and 7)
| # | Do this | Pass when |
|---|---|---|
| G1 | Fresh Windows user or VM: run the installer | Installs, launches, no missing runtime message |
| G2 | Install v1.2.0 over an older version | Settings, vault, bookmarks, extension state survive |
| G3 | Uninstall | App removed; data removal is your choice and is stated |

| Date | Build | Tester | Failures (id: note) |
|---|---|---|---|
