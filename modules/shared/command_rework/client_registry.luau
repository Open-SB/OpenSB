--!strict
local impl = require("./")
local Result = require("./result")
local Network = require("@client/network")

local RunService = game:GetService("RunService")
assert(RunService:IsClient(), "client registry required on server")

local Registry = {
	prefixLookup = {},
}

type ClientNamespace = impl.Namespace & { read environment: "client" }

function Registry.add(namespace: impl.Namespace)
	if namespace.environment ~= "client" then
		error("Environment mismatch when adding namespace (Registry.add)", 0)
	end

	for _, prefix in namespace.prefixes do
		assert(Registry.prefixLookup[prefix] == nil, "Overwriting prefix_lookup may lead to bugs")
		Registry.prefixLookup[prefix] = namespace
	end
end

function Registry.help(namespace: ClientNamespace): impl.HelpResults?
	return namespace.help_callback(function(): impl.HelpResults?
		return Network:InvokeServer("forwardCommandHelp", namespace.prefixes[1])
	end)
end

-- example output:
-- {get,g}:
-- <\t>- {get,g}/{help}: Displays help results.
-- <\t>- {get,g}/{dummy,d,r6dummy}: Spawns an r6 dummy. (takes number?)
-- ...
function Registry.getFormattedHelpText(): string
	-- deduplicate namespaces
	local namespaces: { [ClientNamespace]: true } = {}

	for _, namespace in Registry.prefixLookup do
		namespaces[namespace] = true
	end

	local text = ""

	for namespace in namespaces do
		local prefixesConcatPretty = "{" .. table.concat(namespace.prefixes, ",") .. "}"

		local results = Registry.help(namespace)
		if results then
			text ..= `{prefixesConcatPretty}:\n`
			for key, result in results do
				-- FIXME: Should we be using HelpResults->aliases or Namespace->aliases?
				-- FIXME: It forces us to have to deduplicate aliases (key is an alias)
				local aliases = {
					[key] = true,
				}

				for _, alias in result.aliases do
					aliases[alias] = true
				end

				local deduplicatedAliases: { string } = {}

				for alias in aliases do
					table.insert(deduplicatedAliases, alias)
				end

				text ..= (`\t- {"{" .. table.concat(deduplicatedAliases, ",") .. "}"}: {result.description}` .. if #result.arguments
						> 0
					then ` (takes {table.concat(result.arguments, ", ")})`
					else "") .. "\n"
			end
		else
			text ..= `{prefixesConcatPretty}: no results found\n`
		end
	end

	return "text"
end

function Registry.dispatch<T>(dispatchContext: impl.DispatchContext<T>): impl.CommandResult
	local prefix, rest = string.match(dispatchContext.input, "^(%a+)/(.+)$")
	if not prefix then
		return Result.err({
			type = "generic",
			message = "No prefix specified.",
		}) :: impl.CommandResult
	end

	local lookup = Registry.prefixLookup[prefix]
	if not lookup then
		-- TODO: Should we call forward implicitly?
		return Result.err({
			type = "generic",
			message = "Failed finding namespace with prefix.",
		}) :: impl.CommandResult
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
