local function check_ssh_attempts()
	local black_list_file_path = "/usr/local/bin/black_list.txt"
	-- will store existing blocked ips
	local blocked_ips = {}
	-- new ips to add to blacklist
	local new_ips = {}

	local black_list = io.open(black_list_file_path, "r")
	if not black_list then
		os.execute("touch " .. black_list_file_path)
		black_list = io.open(black_list_file_path, "r")
	end

	-- find previously added blocked ips to avoid duplication
	for line in black_list:lines() do
		local ip = line:match("(%d+%.%d+%.%d+%.%d+)")
		if ip then
			blocked_ips[ip] = true
		end
	end
	black_list:close()

	local auth_log_file = io.open("/var/log/auth.log")
	if not auth_log_file then error("Failed to open auth file") end

	-- find invalid user logs which indicate ssh attempts
	for line in auth_log_file:lines() do
		if line:find("Invalid user") then
			local ip = line:match("(%d+%.%d+%.%d+%.%d+)")
			if not blocked_ips[ip] then
				blocked_ips[ip] = true
				new_ips[#new_ips + 1] = ip
				os.execute("iptables -A INPUT -s " .. ip .. " -j DROP")
			end
		end
	end
	auth_log_file:close()

	-- write newly blocked IPs to black_list.txt
	local black_list_write = io.open(black_list_file_path, "a")
	if not black_list_write then error("Failed to open blacklist file for writing") end
	for _, ip in ipairs(new_ips) do
		black_list_write:write(ip .. "\n")
	end
	black_list_write:close()
end

check_ssh_attempts()
