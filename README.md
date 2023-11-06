# OpenSB

An opensource scriptbuilder for Roblox.

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
