-- atx_power_long.lua
-- Sends a long ATX power button press (~5 seconds) to force-off the machine.
-- This is equivalent to holding the physical power button — it bypasses the OS
-- and cuts power unconditionally. Use with caution: unsaved work will be lost
-- and filesystems may not be cleanly unmounted.
--
-- Usage:
--   jetkvm_control atx_power_long.lua

print("Sending ATX long power press (force off)...")
local result = send_rpc("setATXPowerAction", '{"action": "power-long"}')
print("ATX power-long result: " .. result)
