local stdnse = require "stdnse"
local shortport = require "shortport"
local nsedebug  = require "nsedebug"
local comm = require "comm"

description = [[
This script identifies ports accepting TN3270 terminals which begin the
negotiation with IAC DO TTYPE instead of IAC DO TN3270E.
]]
---
--
-- @usage
-- nmap --script tn3270-info -p 23 -sV <target>
--
-- @output
-- PORT   STATE  SERVICE VERSION
-- 23/tcp open   tn3270  IBM Telnet TN3270
--
-- @changelog
-- 2015-06-10 - v0.1 - created by Soldier of Fortran
-- 2015-08-31 - v0.2 - complete rewrite based on nmap-dev mailing list suggestions
--

author = "Soldier of Fortran"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"version"}

portrule = shortport.version_port_or_service({23, 992}, {"telnet", "telnets"})

-- The Action Section --
action = function(host, port)
  local IAC_DO_TERMINAL_TYPE = string.char(0xff,0xfd,0x18)
  local opts = {recv_before = true}
  local sock, data = comm.tryssl(host, port, '', opts)
  if not sock then
    stdnse.debug('Could not connect')
    return
  end

  if data:find(IAC_DO_TERMINAL_TYPE) ~= nil then
    local IAC_WILL_TERMINAL_TYPE = string.char(0xff,0xfb,0x18)
    local IAC_SEND_TERMINAL_TYPE = string.char(0xff,0xfa,0x18,0x01,0xff,0xf0)
    local IAC_TERMINAL_TYPE      = string.char(0xff,0xfa,0x18,0x00) .. "IBM-3279-4-E" .. string.char(0xff,0xf0)
    local IAC_DO                 = string.char(0xff,0xfd,0x19)
    sock:send(IAC_WILL_TERMINAL_TYPE)
    status, handshake = sock:receive_bytes(6)
    if status == true and handshake == IAC_SEND_TERMINAL_TYPE then
      sock:send(IAC_TERMINAL_TYPE)
      status, handshake = sock:receive_bytes(3)
      if status == true and handshake:sub(1,3) == IAC_DO then
        port.version.product = "IBM Telnet TN3270"
        port.version.name = "tn3270"
        nmap.set_port_version(host, port)
      end
    end
	end -- End telnet 3270 handshake test
  sock:close()
  return
end
