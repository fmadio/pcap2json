#!/opt/fmadio/bin/fmadiolua



local Input = io.stdin


local Tmp = "/mnt/store1/tmp/scrach.json"

IsExit = false

while (IsExit != true) do

	-- read 1K lines and push	
	local T = io.open(Tmp, "w")
	for l=1,10000 do

		local Line = Input:read("*line")
		if (Line == nil) then IsExit = true; break end

		T:write(Line.."\n")
	end
	T:close()

	-- push to ES
	local Cmd = 'curl -s -H "Content-Type: application/x-ndjson" -XPOST 192.168.2.115:9200/_bulk?pretty --data-binary "@'..Tmp..'" | grep -i error'
	print(Cmd)
	os.execute(Cmd)
end



