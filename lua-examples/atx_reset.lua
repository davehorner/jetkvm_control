-- atx_reset.lua
-- Sends an ATX reset signal to the machine connected via the JetKVM ATX Power
-- Control extension module. This is equivalent to pressing the physical reset
-- button on the motherboard (momentary ~200ms pulse).
--
-- Prerequisites:
--   - JetKVM device with ATX Power Control extension module installed
--   - jetkvm_control configured with host/password (jetkvm_control.toml or CLI flags)
--
-- Usage:
--   jetkvm_control atx_reset.lua
--   jetkvm_control -H 192.168.0.100 -P yourpassword atx_reset.lua

print("Sending ATX reset...")
local result = send_rpc("setATXPowerAction", '{"action": "reset"}')
print("ATX reset result: " .. result)
