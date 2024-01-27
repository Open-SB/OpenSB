local MessageType = require("shared/output/messageTypes")

return {
	[MessageType.Log] = Color3.fromRGB(204, 204, 204),
	[MessageType.Warning] = Color3.fromRGB(255, 142, 60),
	[MessageType.Error] = Color3.fromRGB(255, 68, 68),
	[MessageType.Success] = Color3.fromRGB(0, 204, 103),
	[MessageType.Information] = Color3.fromRGB(128, 215, 255),
	[MessageType.System] = Color3.fromRGB(209, 93, 255),
}
