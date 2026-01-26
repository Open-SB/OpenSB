--!strict

local impl = require("../../")
local Result = require("../../result")

type Result<T, E> = Result.Result<T, E>

local function shadow(
	prefixes: { string },
	help: { read aliases: { string }, read arguments: { string }, read description: string }
): impl.Namespace
	return table.freeze({
		prefixes = prefixes,
		run_callback = function<T>(
			context: impl.CommandContext<T>,
			forward: (T) -> impl.CommandResult
		): impl.CommandResult
			return forward(nil)
		end,

		help_callback = function(): impl.HelpResults?
			return table.freeze({ [prefixes[1]] = help })
		end,
	} :: impl.Namespace)
end

return table.freeze({
	shadow(
		{ "c", "run" },
		table.freeze({
			description = "Executes code on the server.",
			aliases = { "run/" },
			arguments = { "code (string)" },
		})
	),
})
