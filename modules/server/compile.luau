local buffer = buffer
local string = string
local pcall = pcall
local tostring = tostring
local require = require

local HttpService = game:GetService("HttpService")

local Log = require("shared/log")

local compilerOptions = table.freeze({
	optimization_level = 1, -- baseline optimization level that doesn't prevent debuggability
	debug_level = 1, -- line info & function names only; sufficient for backtraces
	type_info_level = 0, -- generate for native modules
	coverage_level = 0, -- no code coverage support
	vector_lib = "Vector3",
	vector_ctor = "new",
	vector_type = "Vector3",
})

local compileResult = require("shared/enum")({
	"Success", -- Successful compilation
	"Fail", -- Failure while compiling (is expected to always throw this error due to it being an issue with the input, e.g syntax errors)
	"Error", -- Error while compiling (unknown error)
})

type compilerFunction = (string) -> (typeof(compileResult), buffer | string)
local compilerFunctions: { compilerFunction } = {} -- May error in

if _G.compilerEndpoint and not HttpService.HttpEnabled then
	if not require("shared/wm").isWorkerManager then
		Log.warn(
			'A Luau compiler endpoint was defined, but HttpService.HttpEnabled is not enabled (meaning it can\'t be used). Either enable HttpEnabled or set "compilerEndpoint" config to false to silence this warning.'
		)
	end

	table.insert(
		compilerFunctions,
		function()
			return compileResult.Error,
				"Cannot use Luau compiler endpoint because HttpService.HttpEnabled is not enabled."
		end :: compilerFunction
	)
elseif _G.compilerEndpoint then
	if _G.wakeCompilerEndpoint then
		-- Wake the endpoint (not required but may speed up initial requests if it has slow coldboots)
		task.defer(pcall, HttpService.RequestAsync, HttpService, {
			Url = _G.compilerEndpoint,
			Method = "GET",
		})
	end

	table.insert(
		compilerFunctions,
		function(source: string)
			local success, response = pcall(HttpService.RequestAsync, HttpService, {
				Url = _G.compilerEndpoint, -- Should be compatible with https://github.com/Open-SB/luau-compile
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
				return compileResult.Error, `Error while using Luau compiler endpoint: {response}`
			end

			-- Check if response was an error (includes syntax errors, and request errors shouldn't happen unless the api changes)
			if not response.Success then
				return compileResult.Fail, response.Body
			end

			return compileResult.Success, buffer.fromstring(response.Body)
		end :: compilerFunction
	)
end

if _G.compilerModuleId and require("shared/wm").isWorkerManager then
	local ManagerCommunication = require("shared/wm/communication")
	table.insert(
		compilerFunctions,
		function(source: string)
			return ManagerCommunication:Invoke("compile::module", source) -- Would be unwise to require the compiler modulescript (which could be huge), for every single worker manager
		end :: compilerFunction
	)
elseif _G.compilerModuleId then
	if _G.wakeCompilerModuleId then
		task.defer(pcall, require, _G.compilerModuleId)
	end

	local func: compilerFunction = function(source: string)
		local requireSuccess, compiler = pcall(require, _G.compilerModuleId)
		if not requireSuccess then
			return compileResult.Error, `Error while requiring Luau compiler module: {compiler}`
		end

		local success, result, body = pcall(compiler, source, compilerOptions)
		if not success then
			return compileResult.Error, `Error while using Luau compiler module: {result}`
		end

		if result then
			return compileResult.Success, body
		else
			return compileResult.Fail, body
		end
	end
	table.insert(compilerFunctions, func)

	local WorkerManagers = require("shared/workerManagers")
	WorkerManagers:onInvoke("compile::module", func)
end

if #compilerFunctions == 0 then
	return function()
		return false, "No Luau compilers are defined."
	end
end

return function(source: string): (boolean, string | buffer)
	local errors = {}
	for _, compiler in ipairs(compilerFunctions) do
		local result, body = compiler(source)
		if result == compileResult.Success then
			return true, if type(body) == "buffer" then body else buffer.fromstring(body)
		elseif result == compileResult.Fail then
			return false, if type(body) == "buffer" then buffer.tostring(body) else tostring(body)
		else
			table.insert(errors, if type(body) == "buffer" then buffer.tostring(body) else tostring(body))
		end
	end

	return false, `Unexpected error(s) while compiling Luau:\n{table.concat(errors, "\n")}`
end
