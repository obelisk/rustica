# Rustica Agent GUI
Rustica agent was always envisioned as a commandline utility, similar to standard SSH agents. Unfortunately as Rustica has increased in complexity, the set it and forget it nature of the normal SSH agent model has not scaled well.

Generally SSH agents can be light weight and started in every shell if needed, but since we speak to Yubikeys we have USB handles, since we talk to backends we have cached certificates, and the user might want to flip settings for certificate priority depending on what they're doing at a particular moment.

Thus Rustica agent was reworked into a library only crate and the CLI split out so this crate can exist for a GUI.

## Screenshot
![Image of Rustica Agent GUI](https://user-images.githubusercontent.com/2386877/202832593-e27308cd-c2ec-4e31-b1c9-32f58d533b69.png)


## Why egui?
I wanted a cross platform library that would allow me to make a relatively simple UI without too much effort. If there are better libraries I'm open to switching.

## Why not tui?
I think [tui](https://github.com/fdehau/tui-rs) fills a slightly different niche which was not what I was trying to build with this. However I would love for another crate here, `rustica-agent-tui`, if someone really wants it.

## Current limitation
- No support for multi-mode
- No support for PIV mode
- No support for registration of FIDO keys
- No support for git-config generation