local process = require("@lune/process")
local stdio = require("@lune/stdio")

local branches = require("./branches")

for _, branch in ipairs(branches) do
	if table.find(process.args, branch) then
		return branch
	end
end

local index = stdio.prompt(
	"select",
	"What branch to build for? (Pass it in as argument when running command to skip this)",
	branches
)
return branches[index]
