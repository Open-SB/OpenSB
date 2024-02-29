local Enum = require("shared/enum")

return {
	Server = Enum({
		"KeyExchange",
		"Handshake",
		"Event",
		"Invoke",
	}),
	Client = Enum({
		"Event",
		"InvokeResult",
	}),
}
