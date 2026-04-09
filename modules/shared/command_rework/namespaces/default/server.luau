--!strict

local impl = require("../../")
local Result = require("../../result")

type Result<T, E> = Result.Result<T, E>

return {
	table.freeze({
		prefixes = { "c", "run" },

		run_callback = function<T>(context: impl.CommandContext<T>, forward: nil): impl.CommandResult
			-- We get everything after c/; so this isnt a big problem to implement

			return Result.ok("Not implemented yet")
		end,

		help_callback = function(): impl.HelpResults?
			return {
				c = table.freeze({
					aliases = { "run/" },
					arguments = { "code (string)" },
					description = "Executes code on the server.",
				}),
			}
		end,

		environment = "server" :: "server",
	}) :: impl.Namespace,
}
