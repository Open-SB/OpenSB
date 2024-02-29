return require("shared/enum")({
	"Success", -- No errors occured, successfully processed and ran command.
	"Fail", -- Failed to process command.
	"Error", -- Command threw an error while validating or running.
})
