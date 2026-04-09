--!strict
--!native

local json = require("@std/json")
local fs = require("@lute/fs")

local luaurc
do
	local handle = fs.open("./.luaurc", "r")
	luaurc = assert(json.asObject(json.deserialize(fs.read(handle))), "expected object in luaurc")
	fs.close(handle)
	handle = nil
end

local aliases: { [string]: string } = assert(luaurc["aliases"], "expected aliases key in luaurc") :: any

local Path = require("@std/path")
local AstParser = require("@std/syntax/parser")
local Query = require("@std/syntax/query")
local SyntaxUtils = require("@std/syntax/utils")
local AstTypes = require("@std/syntax/types")
local checkWorkerManagerContract = require("./workerManagerContract")

local ENTRYPOINTS = table.freeze({
	"src/server/workerManager.server.luau",
	"src/client/localWorkerManager.luau",
})

local DEFAULT_OUTPUT_PATH = "checks/checkAll.arrowcrab.json"

local COLORS = {
	entrypoint = "#F2C166",
	server = "#F28B82",
	client = "#8AB4F8",
	shared = "#81C995",
	other = "#C58AF9",
}

type ModuleInfo = {
	path: string,
	dependencies: { string },
	isEntrypoint: boolean,
}

type GraphData = {
	subgraphs: { number },
	nodes: { number },
	edges: { number },
	strings: { string },
}

local function resolveRequirePath(path: string, callerPath: string): string?
	local pieces = string.split(path, "/")

	if string.sub(pieces[1], 1, 1) == "@" then
		pieces[1] = string.sub(pieces[1], 2)

		if pieces[1] == "self" then
			pieces[1] = Path.dirname(callerPath)
		else
			pieces[1] = assert(aliases[pieces[1]], `failed finding alias {pieces[1]}`)
		end
	end

	local final = Path.format(Path.join(unpack(pieces)))

	local stat
	pcall(function(...)
		stat = fs.stat(final)
	end)

	if not stat then
		return final .. ".luau"
	elseif stat.type == "dir" then
		return final .. "/init.luau"
	end

	return nil -- yaml, toml, etc.
end

local function writeFile(file: string, contents: string)
	local handle = fs.open(file, "w")
	fs.write(handle, contents)
	fs.close(handle)
end

local function readFile(file: string): string
	local handle = fs.open(file)
	local source = fs.read(handle)
	fs.close(handle)
	return source
end

local function collectDependencies(file: string, ast: AstTypes.ParseResult): { string }
	local dependencies: { string } = {}
	local seenDependencies: { [string]: boolean } = {}

	Query.findAllFromRoot(ast, SyntaxUtils.isExprCall :: any):forEach(function(expr: AstTypes.AstExprCall)
		if
			SyntaxUtils.isExprGlobal(expr.func :: any)
			and (expr.func :: AstTypes.AstExprGlobal).name.text == "require"
			and #expr.arguments == 1
			and SyntaxUtils.isExprConstantString(expr.arguments[1].node :: any)
		then
			local path = (expr.arguments[1].node :: AstTypes.AstExprConstantString).token.text
			local resolved = resolveRequirePath(path, file)
			if resolved and not seenDependencies[resolved] then
				seenDependencies[resolved] = true
				table.insert(dependencies, resolved)
			end
		end
	end)

	return dependencies
end

local function getNodeColor(file: string, isEntrypoint: boolean): string
	if isEntrypoint then
		return COLORS.entrypoint
	elseif string.find(file, "src/server/", 1, true) or string.find(file, "modules/server/", 1, true) then
		return COLORS.server
	elseif string.find(file, "src/client/", 1, true) or string.find(file, "modules/client/", 1, true) then
		return COLORS.client
	elseif string.find(file, "src/shared/", 1, true) or string.find(file, "modules/shared/", 1, true) then
		return COLORS.shared
	else
		return COLORS.other
	end
end

local function buildArrowCrabGraph(entrypoints: { string }): GraphData
	local visitState: { [string]: "visiting" | "done" } = {}
	local modulesByPath: { [string]: ModuleInfo } = {}
	local orderedPaths: { string } = {}

	local function visit(file: string, isEntrypoint: boolean)
		local state = visitState[file]
		if state == "done" then
			if isEntrypoint then
				modulesByPath[file].isEntrypoint = true
			end

			return
		elseif state == "visiting" then
			error(`cyclic require graph detected involving {file}`)
		end

		visitState[file] = "visiting"

		local dependencies = collectDependencies(file, AstParser.parse(readFile(file)))
		for _, dependency in dependencies do
			visit(dependency, false)
		end

		modulesByPath[file] = {
			path = file,
			dependencies = dependencies,
			isEntrypoint = isEntrypoint,
		}

		visitState[file] = "done"
		table.insert(orderedPaths, file)
	end

	for _, entrypoint in entrypoints do
		visit(entrypoint, true)
	end

	local strings: { string } = {}
	local stringToIndex: { [string]: number } = {}
	local nodeIds: { [string]: number } = {}
	local nodes: { number } = {}
	local edges: { number } = {}

	local function internString(value: string): number
		local existing = stringToIndex[value]
		if existing ~= nil then
			return existing
		end

		local index = #strings
		table.insert(strings, value)
		stringToIndex[value] = index
		return index
	end

	for id, path in orderedPaths do
		local nodeId = id - 1
		local moduleInfo = modulesByPath[path]
		nodeIds[path] = nodeId

		table.insert(nodes, nodeId)
		table.insert(nodes, internString(moduleInfo.path))
		table.insert(nodes, internString(getNodeColor(path, moduleInfo.isEntrypoint)))
	end

	for _, path in orderedPaths do
		local moduleInfo = modulesByPath[path]
		local targetId = nodeIds[path]
		for _, dependency in moduleInfo.dependencies do
			table.insert(edges, nodeIds[dependency])
			table.insert(edges, 0)
			table.insert(edges, targetId)
			table.insert(edges, 0)
		end
	end

	return {
		subgraphs = {},
		nodes = nodes,
		edges = edges,
		strings = strings,
	}
end

local function writeArrowCrabGraph(outputPath: string, graphData: GraphData)
	local handle = fs.open(outputPath, "w")
	fs.write(handle, json.serialize(graphData :: any))
	fs.close(handle)
end

local argv = { ... }

if argv[2] == "--graph" then
	local providedOutputPath = argv[3]
	local outputPath = (providedOutputPath :: string?) or DEFAULT_OUTPUT_PATH

	writeArrowCrabGraph(outputPath, buildArrowCrabGraph(ENTRYPOINTS))
	print(`wrote ArrowCrab (https://hemileia.club/arrowcrab/) graph to {outputPath}`)
else
	local patch = argv[2] == "--patch"
	local allPaths = {}

	for _, entrypoint in ENTRYPOINTS do
		local function visit(path: string)
			allPaths[path] = true -- mark

			local source = readFile(path)
			local ast = AstParser.parse(source)
			local globalsMap = checkWorkerManagerContract(ast.root, path)

			if patch then
				local globalsArray = {}
				for global in globalsMap do
					table.insert(globalsArray, global)
				end

				if #globalsArray > 0 then
					local pretext = `local {table.concat(globalsArray, ", ")} = {table.concat(globalsArray, ", ")}\n\n`
					source = pretext .. source

					writeFile(path, source)
				end
			end

			for _, dependency in collectDependencies(path, ast) do
				visit(dependency)
			end
		end

		visit(entrypoint)
	end
end
