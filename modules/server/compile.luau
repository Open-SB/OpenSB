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

return function(source: string): (boolean, string)
	if not HttpService.HttpEnabled then
		return false, "HttpService is disabled, cannot use online Luau compiler."
	end

	-- https://github.com/Open-SB/luau-compile
	local success, response = pcall(HttpService.RequestAsync, HttpService, {
		Url = "https://luau-compile.shuttleapp.rs/compile",
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

	-- Check if response was an error
	if not response.Success then
		return false, response.Body
	end

	-- Check if the bytecode is an error message
	if buffer.readu8(buffer.fromstring(response.Body), 0) == 0 then
		return false, string.sub(response.Body, 2)
	end

	return true, response.Body
end
