--!strict

local impl = require("./")
local Result = require("result")
local Output = require("@server/output")

type OldCtx = {
	Player: Player,
	Data: unknown,
}

local function defineSimple(
	initCallback: (
		define: (name: string, fn: (ctx: OldCtx, { string }) -> string?) -> (),
		defineValidator: (name: string, fn: (ctx: OldCtx, { string }) -> (boolean, string)) -> ()
	) -> (),

	tomlInit: {
		[string]: {
			aliases: { string },
			description: string,
			arguments: { string }?,
		},

		["_prefixes"]: { string },
	}
): impl.Namespace
	local lookupTable: {
		[string]: {
			fn: (OldCtx, { string }) -> string?,
			validate: (OldCtx, { string }) -> (boolean, string),
			generatedHelpText: string?,
		},
	} =
		{}

	local function define(name: string, fn: (ctx: OldCtx, { string }) -> string?)
		local t: any = lookupTable[name]
		if t then
			t.run = fn
		else
			lookupTable[name] = {
				run = fn,
			} :: any
		end
	end

	local function defineValidator(name: string, fn: (ctx: OldCtx, { string }) -> (boolean, string))
		local t = lookupTable[name]
		if t then
			t.validate = fn
		else
			lookupTable[name] = {
				validate = fn,
			} :: any
		end
	end

	local function handleFragment<T>(context: impl.CommandContext<T>, fragment: string): impl.CommandResult
		local arguments = string.split(fragment, "/")
		local name = table.remove(arguments, 1)
		local commandEntry = lookupTable[name or ""]

		if not commandEntry then
			return Result.err({
				message = "Failed finding command.",
				type = "parse",
			}) :: impl.CommandResult
		end

		local success, error = true, nil
		local ctx: OldCtx = {
			Player = context.player,
			Data = context.data,
		}

		if commandEntry.validate then
			success, error = commandEntry.validate(ctx, arguments)
		end

		if success then
			return Result.ok(commandEntry.fn(ctx, arguments)) :: impl.CommandResult
		else
			return Result.err({
				message = error,
				type = "validation",
			} :: impl.Error) :: impl.CommandResult
		end
	end

	initCallback(define, defineValidator)

	local prefixes: { string } = tomlInit._prefixes
	local helpLookupTable: impl.HelpResults = {}

	do
		for key, value in tomlInit do
			if key == "_prefixes" then
				continue
			end

			-- only register key (main alias) to avoid clogging help entries
			helpLookupTable[key] = table.freeze({
				description = value.description,
				aliases = value.aliases,
				arguments = value.arguments or { "unknown" },
			})

			for _, alias in value.aliases do
				-- FIXME: hacky alias init. we shouldn't do this in production!
				lookupTable[alias] = lookupTable[key]
			end
		end
	end

	table.freeze(helpLookupTable)

	return table.freeze({
		prefixes = prefixes,

		run_callback = function<T>(context: impl.CommandContext<T>, forward: nil): impl.CommandResult
			local fragments: { string } = string.split(context.input, " ")
			local results = {}

			for _, fragment in fragments do
				table.insert(results, handleFragment(context, fragment))
			end

			for _, result in results do
				-- manually output because we have alot of commands
				if Result.is_ok(result) then
					local message = Result.unwrap(result)
					if message ~= nil then
						Output:appendTo(context.player, Output.MessageType.Success, message)
					end
				else
					Output:appendTo(
						context.player,
						Output.MessageType.Error,
						(Result.unwrap_err(result) :: impl.Error).message
					)
				end
			end

			-- nil return -> do not create an output line for us
			return Result.ok(nil) :: impl.CommandResult
		end,

		help_callback = function(): impl.HelpResults?
			return helpLookupTable
		end,

		environment = "server" :: "server",
	}) :: impl.Namespace
end

return defineSimple
