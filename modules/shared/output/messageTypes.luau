-- Values should be types that are serializable by remotes.

local MessageTypes = {
	Log = 0,
	Warning = 1,
	Error = 2,
	Success = 3,
	Information = 4,
	System = 5,
}

-- Create a lookup table to allow checking if a type exists from a value.
for key, value in MessageTypes do
	MessageTypes[value] = key
end

return MessageTypes
