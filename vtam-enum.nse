local stdnse    = require "stdnse"
local shortport = require "shortport"
local tn3270    = require "tn3270"
local brute     = require "brute"
local creds     = require "creds"
local unpwdb    = require "unpwdb"

description = [[
Many mainframes use VTAM screens to connect to various applications
(CICS, IMS, TSO, and many more).

This script attempts to brute force those VTAM application IDs.

This script is based on mainframe_brute by Dominic White
(https://github.com/sensepost/mainframe_brute). However, this script
doesn't rely on any third party libraries or tools and instead uses
the NSE TN3270 library which emulates a TN3270 screen in lua.

Application IDs only allows for 8 byte IDs, that is the only specific rule
found for application IDs.
]]

--@args idlist Path to list of application IDs to test.
--  Defaults to <code>nselib/data/usernames.lst</code>.
--@args vtam-enum.commands Commands in a semi-colon seperated list needed
--  to access VTAM. Defaults to <code>nothing</code>.
--@args vtam-enum.path Folder used to store valid transaction id 'screenshots'
--  Defaults to <code>None</code> and doesn't store anything.
--@args vtam-enum.macros When set to true does not prepend the application ID
--  with 'logon applid()'. Defaults is <code>false</code>.
--
--@usage
-- nmap --script vtam-enum -p 23 <targets>
--
-- nmap --script vtam-enum --script-args idlist=defaults.txt,
-- vtam-enum.command="exit;logon applid(logos)",vtam-enum.macros=true
-- vtam-enum.path="/home/dade/screenshots/" -p 23 -sV <targets>
--
--@output
-- PORT   STATE SERVICE VERSION
-- 23/tcp open  tn3270  IBM Telnet TN3270
-- | vtam-enum:
-- |   VTAM Application ID:
-- |     applid:TSO - Valid credentials
-- |     applid:CICSTS51 - Valid credentials
-- |_  Statistics: Performed 14 guesses in 5 seconds, average tps: 2
--
-- @changelog
-- 2015-07-04 - v0.1 - created by Soldier of Fortran
-- 2015-11-04 - v0.2 - significant upgrades and speed increases
--

author = "Philip Young aka Soldier of Fortran"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service({23,992,623}, "tn3270")

--- Saves the Screen generated by the VTAM command to disk
--
-- @param filename string containing the name and full path to the file
-- @param data contains the data
-- @return status true on success, false on failure
-- @return err string containing error message if status is false
local function save_screens( filename, data )
	local f = io.open( filename, "w")
	if not f then return false, ("Failed to open file (%s)"):format(filename) end
	if not(f:write(data)) then return false, ("Failed to write file (%s)"):format(filename) end
	f:close()
	return true
end

--- Compares two screens and returns the difference as a percentage
--
-- @param1 the original screen
-- @param2 the screen to compare to
local function screen_diff( orig_screen, current_screen )
	if orig_screen == current_screen then return 100 end
	if #orig_screen == 0 or #current_screen == 0 then return 0 end
	m = 1
	for i =1 , #orig_screen do
		if orig_screen:sub(i,i) == current_screen:sub(i,i) then
			m = m + 1
		end
	end
	return (m/1920)*100
end

Driver = {
	new = function(self, host, port, options)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    o.options = options
    o.tn3270 = Telnet:new()
    return o
  end,
	connect = function( self )
    local status, err = self.tn3270:initiate(self.host,self.port)
    if not status then
      stdnse.debug("Could not initiate TN3270: %s", err )
      return false
    end
    return true
  end,
	disconnect = function( self )
		self.tn3270:disconnect()
		self.tn3270 = nil
	end,
	login = function (self, user, pass) -- pass is actually the username we want to try
		local path = self.options['key2']
		local macros = self.options['key3']
		local cmdfmt = "logon applid(%s)"
		local type = "applid"
		-- instead of sending 'logon applid(<appname>)' when macros=true
		-- we try to logon with just the command
		if macros then
			cmdfmt = "%s"
			type ="macro"
		end
		stdnse.verbose(2,"Trying VTAM ID: %s", pass)

		local previous_screen = self.tn3270:get_screen_raw()
		self.tn3270:send_cursor(cmdfmt:format(pass))
		self.tn3270:get_all_data()
		self.tn3270:get_screen_debug()
		local current_screen = self.tn3270:get_screen_raw()

		if (self.tn3270:find('UNABLE TO ESTABLISH SESSION')  or
			self.tn3270:find('COMMAND UNRECOGNIZED')         or
			self.tn3270:find('SESSION NOT BOUND')            or
			self.tn3270:find('INVALID COMMAND')              or
			self.tn3270:find('PARAMETER OMITTED')            or
			self.tn3270:find('REQUERIDO PARAMETRO PERDIDO')  or
			self.tn3270:find('Your command is unrecognized') or
			self.tn3270:find('invalid command or syntax')    or
			self.tn3270:find('UNSUPPORTED FUNCTION')         or
			self.tn3270:find('REQSESS error')                or
			self.tn3270:find('syntax invalid')               or
			self.tn3270:find('INVALID SYSTEM')               or
			self.tn3270:find('NOT VALID')                    or
			self.tn3270:find('COMMAND UNRECOGNIZED')         or
			self.tn3270:find('INVALID USERID, APPLID') )     or -- thanks goes to Domonic White for creating these
			screen_diff(previous_screen, current_screen) > 75 then
			-- Looks like an invalid APPLID.
			return false,  brute.Error:new( "Invalid VTAM Application ID" )
		else
			stdnse.verbose(2,"Valid Application ID: %s",string.upper(pass))
      if path ~= nil then
        stdnse.verbose(2,"Writting screen to: %s", path..string.upper(pass)..".txt")
        status, err = save_screens(path..string.upper(pass)..".txt",self.tn3270:get_screen())
        if not status then
          stdnse.verbose(2,"Failed writting screen to: %s", path..string.upper(pass)..".txt")
        end
      end
			return true, creds.Account:new(type,string.upper(pass), creds.State.VALID)
		end
	end
}

--- Tests the target to see if we can use logon applid(<id>) for enumeration
--
-- @param host host NSE object
-- @param port port NSE object
-- @param commands optional script-args of commands to use to get to VTAM
-- @return status true on success, false on failure
local function vtam_test( host, port, commands, macros)
	local tn = Telnet:new()
	local status, err = tn:initiate(host,port)
	stdnse.debug("Testing if VTAM and 'logon applid' command supported")
	stdnse.debug("Connecting TN3270 to %s:%s", host.targetname or host.ip, port.number)

	if not status then
		stdnse.debug("Could not initiate TN3270: %s", err )
  	return false
  end

	stdnse.debug("Displaying initial TN3270 Screen:")
	tn:get_screen_debug() -- prints TN3270 screen to debug

	if commands ~= nil then
		local run = stdnse.strsplit(";%s*", commands)
		for i = 1, #run do
			stdnse.debug(2,"Issuing Command (#%s of %s) or %s", i, #run ,run[i])
			tn:send_cursor(run[i])
			tn:get_screen_debug()
		end
  end
	stdnse.debug("Sending VTAM command: IBMTEST")
  tn:send_cursor('IBMTEST')
	tn:get_all_data()
	tn:get_screen_debug()
	local isVTAM = false
  if tn:find('IBMECHO ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') then
		stdnse.debug("IBMTEST Returned: IBMECHO ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.")
		stdnse.debug("VTAM Test Success!")
		isVTAM = true
	end

	if not macros then
		-- now testing if we can send 'logon applid(<id>)'
		-- certain systems interpret 'logon' as the tso logon
		tn:send_cursor('LOGON APPLID(FAKE)')
		tn:get_all_data()
		tn:get_screen_debug()
		if tn:find('INVALID USERID') then
			isVTAM = false
		end
		tn:disconnect()
	end
	return isVTAM
end

-- Checks if it's a valid VTAM name
local valid_vtam = function(x)
  return (string.len(x) <= 8 and string.match(x,"[%w@#%$]"))
end

action = function(host, port)
	local vtam_id_file = stdnse.get_script_args("idlist")	or "nselib/data/usernames.lst"
	local path = stdnse.get_script_args(SCRIPT_NAME .. '.path') -- Folder for 'screen shots'
	local macros = stdnse.get_script_args(SCRIPT_NAME .. '.macros') or false -- Commands to send to get to VTAM
	local commands = stdnse.get_script_args(SCRIPT_NAME .. '.commands') -- Commands to send to get to VTAM
	-- this is a cheap hack so we can use unpwdb iterators but still
	-- able to provide our own usefull argument name instead of 'userdb'
	nmap.registry.args["userdb"] = vtam_id_file
	if vtam_test(host, port, commands, macros) then
		local options = { key1 = commands, key2 = path, key3=macros }
	 	stdnse.verbose("Starting VTAM Application ID Enumeration")
		if path ~= nil then stdnse.verbose(2,"Saving Screenshots to: %s", path) end
	 	local engine = brute.Engine:new(Driver, host, port, options)
	 	engine.options.script_name = SCRIPT_NAME
		engine:setPasswordIterator(unpwdb.filter_iterator(brute.usernames_iterator(),valid_vtam))
	 	engine.options.passonly = true
	 	engine.options:setTitle("VTAM Application ID")
	 	local status, result = engine:start()
		return result
	else
	 	return "Not VTAM or 'logon applid' command not accepted. Try with script arg 'vtam-enum.macros=true'"
	end

end
