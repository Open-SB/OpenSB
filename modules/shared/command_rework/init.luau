--!strict

local Result = require("./result")

--[[
Parse:
Error occured whilst parsing command: {message}

Invoke:
Runtime error occured in command: {message}

Generic:
Generic error occured in command: {message}

Validation:
Validation error occured in command: {message}
]]
export type Error = { type: "parse" | "invoke" | "generic" | "validation", message: string }

export type HelpResults = { [string]: { read description: string, read aliases: { string }, read arguments: { string } } }

export type Namespace = {
	read prefixes: { string },
	read run_callback: <T>(
		ctx: CommandContext<T>,
		forward: ((data: T) -> CommandResult)? --[[ !! ONLY USABLE ON CLIENT !! ]]
	) -> CommandResult, --[[ string is the successful output text ]]

	--[[
	sb/permBan (args: Player) (aliases: sb/pb): Ban a player forever

	if a help_callback is NOT defined:
	player: g/help
	terminal:
	g: no help callback implemented
	sb: no help callback implemented
	c: no help callback implemented
	]]
	read help_callback: () -> HelpResults?,
	read environment: "server" | "client",
}

export type RunContext = "chat" | "command_bar"

export type CommandContext<Data> = {
	player: Player,
	context: RunContext,
	-- Excludes the beginning prefix (player: "g/sr" -> command receives "sr", and everything after g/)
	input: string,

	data: Data,
}

export type DispatchContext<Data> = {
	player: Player,
	context: RunContext,
	-- Raw input
	input: string,

	data: Data,
}

export type CommandResult = Result.Result<string, Error>

return {}
