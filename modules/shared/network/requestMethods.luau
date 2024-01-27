-- Values should be types that are serializable by remotes.

return {
	Server = {
		KeyExchange = 0,
		Handshake = 1,
		Event = 2,
		Invoke = 3,
	},
	Client = {
		Event = 0,
		InvokeResult = 1,
	},
}
