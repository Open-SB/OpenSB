--!strict
local impl = require("./")
local Result = require("./result")
local Network = require("@server/network")

local RunService = game:GetService("RunService")
assert(RunService:IsServer(), "server registry required on client")

local Registry = {
	prefixLookup = {},
}

function Registry.add(namespace: impl.Namespace)
	if namespace.environment ~= "server" then
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
		return Result.err({
			type = "generic",
			message = "Failed finding namespace with prefix.",
		})
	end

	return lookup.run_callback({
		player = dispatchContext.player,
		context = dispatchContext.context,
		input = rest or "",
		data = dispatchContext.data,
	}, nil)
end

Network:RegisterFunction("forwardCommand", function(player: Player, ctx: any): impl.CommandResult?
	if typeof(ctx) ~= "table" then
		return nil
	end

	if typeof(ctx.context) ~= "string" or not (ctx.context == "chat" or ctx.content == "command_bar") then
		return nil
	end

	if typeof(ctx.input) ~= "string" then
		return nil
	end

	local safeDispatchCtx: impl.DispatchContext<unknown> = {
		player = player,
		context = ctx.context :: any,
		input = ctx.input,
		data = ctx.data,
	}

	return Registry.dispatch(safeDispatchCtx)
end)

return table.freeze(Registry)
