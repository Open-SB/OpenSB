local a,b,c,d,e,f,g,h,i,j,k,l,m=os.clock(),game,task,script,setfenv,os,math,Instance,coroutine,ipairs,require,print,warn e(1,{})local n=k'shared/log'n
.debug'Fetching assets'local o,p,q=d.Parent,d:WaitForChild'modules':Clone(),d:WaitForChild'clientScripts':Clone()do local r=q:WaitForChild'sbActor':
WaitForChild'sb'r:SetAttribute('_descendants',#r:GetDescendants())end do local r=o:GetAttributeChangedSignal'canDestroy'while not o:GetAttribute
'canDestroy'do r:Wait()end end do local r=i.running()c.defer(function()o:Destroy()d:Destroy()d=nil i.resume(r)end)i.yield()end local r,s=b:GetService
'Players',b:GetService'RunService'n.debug'Loading modules'local t=k(p)local u,v=t.require'network',t.require'functions'n.debug'Loading systems'do
local w,x=function()end,function(w)n.debug('Checking if '..w.Name..' can join...')if not s:IsStudio()and w.AccountAge<7 then n.debug(w.Name..
"'s account age is too young (<7).")w:Kick[[Your account age has to be atleast one week old to play this game.]]return end n.debug('Checking ban on '
..w.Name..'...')do n.debug('Loading SB client on '..w.Name..'...')local x=w:FindFirstChildOfClass'PlayerGui'if not x then n.debug(w..
' had no player gui.')w:Kick'PlayerGui was not found while loading.'return end local y=q:Clone()y.Name=v.randomInstanceName()y.Archivable=false local
z=y:WaitForChild'sbActor'z.Archivable=false local A=z:WaitForChild'sb'A.Name=v.randomInstanceName()A.Archivable=false local B=y:WaitForChild'sandbox'B
.Name=v.randomInstanceName()B.Archivable=false A:SetAttribute(u.attributeName,u.attributeValue)y.Parent=x c.delay(1,function()y:Destroy()z:Destroy()A:
Destroy()B:Destroy()end)end end r.PlayerAdded:Connect(x)r.PlayerRemoving:Connect(w)for y,z in j(r:GetPlayers())do c.spawn(x,z)end end n.debug
'Waiting for modules...'t.waitForModulesToLoad()n.debug'Finalizing...'r.CharacterAutoLoads=true for w,x in j(r:GetPlayers())do c.defer(x.LoadCharacter
,x)end n.print('Loaded in '..g.round((f.clock()-a)*1000)..'ms.')