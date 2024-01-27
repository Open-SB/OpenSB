-- Values should be types that are serializable by remotes.

local InputContexts = {
	Chat = 0,
	CommandBar = 1,
}

-- Create a lookup table to allow checking if a type exists from a value.
for key, value in InputContexts do
	InputContexts[value] = key
end

return InputContexts
