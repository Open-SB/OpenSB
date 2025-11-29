--!strict

local impl = require("../../")
local Result = require("../../result")

type Result<T, E> = Result.Result<T, E>

return {
	table.freeze({
		prefixes = { "get", "g" },

		run_callback = function<T>(
			context: impl.CommandContext<T>,
			forward: (T) -> impl.CommandResult
		): impl.CommandResult
			return forward(nil)
		end,

		help_callback = function(forward: () -> impl.HelpResults?): impl.HelpResults?
			return forward()
		end,

		environment = "client" :: "client",
	}) :: impl.Namespace,
}
