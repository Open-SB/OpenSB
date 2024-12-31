# OpenSB

An opensource scriptbuilder for Roblox.

#### Notice

By default this depends on https://luau-compile-mapk.shuttle.app.rs/ ([running this](https://github.com/Open-SB/luau-compile)).

Which is being used to compile Luau sourcecode into bytecode (only for localscripts). As there is no good solution for compiling Luau in Luau at the moment (that is small & lightweight).
<br>
As a bonus using an full Luau compiler allows us to generate bytecode with optimizations turned on.

This is being used in [compile.luau](https://github.com/Open-SB/OpenSB/blob/main/modules/server/compile.luau), and I encourage you to change it to using your own hosted version (it's free with shuttle).

## Getting Started

You will need to [install aftman](https://github.com/LPGhatguy/aftman#aftman) first to get the required tools, or you can manually install them yourself (found in the [aftman.toml file](https://github.com/Open-SB/OpenSB/blob/main/aftman.toml)).

After you have installed aftman, run:

```bash
aftman install
```

## Building & testing

To build the place from scratch, use:

```bash
npm run dev && rojo build -o "OpenSB.rbxlx"
```

Next, open `OpenSB.rbxlx` in Roblox Studio and start the Rojo server:

```bash
rojo serve
```

Then when you want to test your changes, use:

```bash
npm run dev
```

(The --watch flag on darklua would've worked if the modules folder was in src, but doing that would process a duplicate of the modules folder)

To build the "production" version, use:

```bash
npm run build
```

For more help, check out the [Rojo](https://rojo.space/docs) and [darklua](https://darklua.com/docs) documentation.
