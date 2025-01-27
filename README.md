# OpenSB

An opensource scriptbuilder for Roblox.

#### Notice

By default this depends on https://luau-compile-mapk.shuttle.app.rs/ ([running this](https://github.com/Open-SB/luau-compile)).

Which is being used to compile Luau sourcecode into bytecode (only for localscripts). As there is no good solution for compiling Luau in Luau at the moment (that is small & lightweight).
<br>
As a bonus using an full Luau compiler allows us to generate bytecode with optimizations turned on.

This is being used in [compile.luau](https://github.com/Open-SB/OpenSB/blob/main/modules/server/compile.luau), and I encourage you to change it to using your own hosted version (it's free with shuttle).

## Getting Started

You will need to [install aftman](https://github.com/LPGhatguy/aftman#aftman) first to get the required tooling.

After you have installed aftman, run:

```bash
aftman install
```

## Configuration

This uses a lune script to aid in building the project with provided configuration ([source available here](https://github.com/Open-SB/OpenSB/blob/main/.lune/build)).

Custom configurations can be made in a ".config.toml" file (ignored in the .gitinore, and should be placed in the root folder), and uses the same format as the ["default.toml" in .lune/build/config](https://github.com/Open-SB/OpenSB/blob/main/.lune/build/config/default.toml) (also where you should look for all availble configurations).

Any defined fields under the selected branch will replace the default value. To make configurations that apply to any branch use the "global" branch.

Example:

```toml
[global]
scriptHostKey = "secret"

[dev]
workerThreads = 4

[prod]
workerThreads = 12
```

(The script host key will be set to "secret" for all branches, and workerThreads will be set to 4 while in dev, and 12 while in prod).

Custom darklua rules can be provided under the "darkluaRules" field for the selected branch (will replace default rules!).

## Building & testing

To build the place from scratch, use:

```bash
lune run build dev && rojo build -o "OpenSB.rbxlx"
```

Next, open `OpenSB.rbxlx` in Roblox Studio and start the Rojo server:

```bash
rojo serve
```

Then when you want to test your changes, use:

```bash
lune run build dev
```

(The --watch flag on darklua would've worked if the modules folder was in src, but doing that would process a duplicate of the modules folder)

To build the "production" version, use:

```bash
lune run build prod
```

A list of "branches" is visible when running the build script without providing a branch:

```bash
lune run build
```

For more help, check out the [Rojo](https://rojo.space/docs) and [darklua](https://darklua.com/docs) documentation.
