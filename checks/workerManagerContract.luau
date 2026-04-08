--!native
--!strict

local Parser = require("@std/syntax/parser")
local AstVisitor = require("@std/syntax/visitor")
local utils = require("@std/syntax/utils")
local types = require("@std/syntax/types")
local tableext = require("@std/tableext")
local fs = require("@lute/fs")
local pathlib = require("@std/path")

local filePath = assert(({ ... })[2], "no file given")
filePath = pathlib.normalize(filePath)

local fileHandle = fs.open(pathlib.format(filePath), "r")
local root = Parser.parseBlock(fs.read(fileHandle))
fs.close(fileHandle)

local visitor = AstVisitor.create(nil)
local functionScopes: { types.AstExprFunction } = {}
local functionNameMap: { [types.AstExprFunction]: {
	name: string?,
	location: types.Span,
} } = {}

local function getScopePath()
	return table.concat(
		tableext.map(functionScopes, function(expr: types.AstExprFunction)
			return if functionNameMap[expr] then functionNameMap[expr].name else "<anonymous>"
		end),
		"->"
	)
end

local function formatSpan(span: types.Span, filePath: string)
	return `{filePath}:{span.beginLine}:{span.beginColumn}-{span.endColumn}`
end

visitor.visitExprGlobal = function(expr: types.AstExprGlobal)
	if #functionScopes > 0 then
		-- not in root scope, in a function
		print(
			`usage of global '{expr.name.text}' @ {formatSpan(expr.location, filePath)} in scope {getScopePath()} is unsafe`
		)
	end

	return true
end

local disable = function()
	return false
end

visitor.visitStatTypeFunction = disable
visitor.visitTypeFunction = disable

visitor.visitStatFunction = function(stat: types.AstStatFunction)
	functionNameMap[stat.func] = {
		name = utils.isExprGlobal(stat.name :: any) and (stat.name :: types.AstExprGlobal).name.text or nil,
		location = stat.location,
	}

	AstVisitor.visit(stat.func, visitor)

	-- skip the AstExprGlobalin this stat function
	return false
end

visitor.visitStatLocalFunction = function(stat: types.AstStatLocalFunction)
	functionNameMap[stat.func] = {
		name = stat.name.name.text,
		location = stat.location,
	}

	return true
end

visitor.visitStatLocalDeclaration = function(stat: types.AstStatLocal)
	for index, value in stat.values do
		functionNameMap[value.node :: types.AstExprFunction] = {
			name = utils.isExprFunction(value.node :: any) and stat.variables[index].node.name.text or nil,
			location = value.node.location,
		}
	end
	return true
end

visitor.visitExprFunction = function(expr: types.AstExprFunction)
	table.insert(functionScopes, expr)

	return true
end

visitor.visitExprFunctionEnd = function(expr: types.AstExprFunction)
	table.remove(functionScopes)
end

AstVisitor.visit(root, visitor)
