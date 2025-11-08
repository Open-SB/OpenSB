--!strict
local impl = require("./")
local Result = require("./result")
local Network = require("@client/network")

local RunService = game:GetService("RunService")
assert(RunService:IsClient(), "client registry required on server")

local Registry = {
	prefixLookup = {},
}

function Registry.add(namespace: impl.Namespace)
	if namespace.environment ~= "client" then
		error("Environment mismatch when adding namespace (Registry.add)", 0)
	end

	for _, prefix in namespace.prefixes do
		assert(Registry.prefixLookup[prefix] == nil, "Overwriting prefix_lookup may lead to bugs")
		Registry.prefixLookup[prefix] = namespace
	end
end

function Registry.dispatch<T>(dispatchContext: impl.DispatchContext<T>): impl.CommandResult
	local prefix, rest = string.match(dispatchContext.input, "^(%a+)/(.+)$")
	if not prefix then
		return Result.err({
			type = "generic",
			message = "No prefix specified.",
		})
	end

	local lookup = Registry.prefixLookup[prefix]
	if not lookup then
		-- TODO: Should we call forward implicitly?
		return Result.err({
			type = "generic",
			message = "Failed finding namespace with prefix.",
		})
	end

	local input = rest or ""

	local commandContext: impl.CommandContext<T> = {
		player = dispatchContext.player,
		context = dispatchContext.context,
		input = input,
		data = dispatchContext.data,
	}

	return lookup.run_callback(commandContext, function(data: T): impl.CommandResult
		return assert(
			Network:InvokeServer("forwardCommand", {
				context = dispatchContext.context,
				input = input,
				data = data,
			}),
			"server returned nil when forwarding command"
		)
	end)
end

return table.freeze(Registry)
