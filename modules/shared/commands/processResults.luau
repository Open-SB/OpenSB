-- Values should be types that are serializable by remotes.

return {
	Success = 0, -- No errors occured, successfully processed and ran command.
	Fail = 1, -- Failed to process command.
	Error = 2, -- Command threw an error while validating or running.
}
