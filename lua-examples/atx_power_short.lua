-- atx_power_short.lua
-- Sends a short ATX power button press (~200ms) to the machine connected via
-- the JetKVM ATX Power Control extension module. This is the normal power
-- toggle: turns the machine on if off, or triggers a graceful shutdown if the
-- OS is configured to handle ACPI power button events.
--
-- Usage:
--   jetkvm_control atx_power_short.lua

print("Sending ATX short power press...")
local result = send_rpc("setATXPowerAction", '{"action": "power-short"}')
print("ATX power-short result: " .. result)
