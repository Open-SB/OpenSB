local buffer = buffer
local string = string
local pcall = pcall

local HttpService = game:GetService("HttpService")

local compilerOptions = table.freeze({
	optimization_level = 1, -- baseline optimization level that doesn't prevent debuggability
	debug_level = 1, -- line info & function names only; sufficient for backtraces
	type_info_level = 0, -- generate for native modules
	coverage_level = 0, -- no code coverage support
	vector_lib = "Vector3",
	vector_ctor = "new",
	vector_type = "Vector3",
})

return function(source: string): (boolean, string | buffer)
	if not HttpService.HttpEnabled then
		return false, "HttpService is disabled, cannot use online Luau compiler."
	end

	local success, response = pcall(HttpService.RequestAsync, HttpService, {
		Url = "https://luau-compile-mapk.shuttle.app/compile", -- Check: https://github.com/Open-SB/luau-compile (I recommend hosting your own version, it's free with shuttle)
		Method = "POST",
		Headers = {
			["Content-Type"] = "application/json",
		},
		Body = HttpService:JSONEncode({
			source = source,
			options = compilerOptions,
		}),
	})

	if not success then
		return false, `Error while using online Luau compiler: {response}`
	end

	-- Check if response was an error (includes syntax errors)
	if not response.Success then
		return false, response.Body
	end

	return true, buffer.fromstring(response.Body)
end
