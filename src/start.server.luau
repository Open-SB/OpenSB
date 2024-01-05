--[[
    This script will be placed under the client sb and the client sandbox. Its runcontext is changed accordingly (check default.project.json).

    This is done to improve persistancy on client scripts, as they should be basically be impossible to stop without using exploits or causing errors to be thrown.
    We don't do this on the server as we don't allow script execution until after the server scripts have actually destroyed themselves,
    and because doing so could allow people to :Clone() the script (modulescript) and parent it to themselves so they can decompile it.
]]

task.spawn(require, script.Parent)
