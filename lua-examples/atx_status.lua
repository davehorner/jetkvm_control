-- atx_status.lua
-- Queries the current ATX LED state from the JetKVM ATX Power Control extension.
-- Returns "power" (bool) and "hdd" (bool) indicating whether the power LED and
-- HDD activity LED are currently lit.
--
-- NOTE: The JetKVM reads the power LED state from the motherboard header pin.
-- Some motherboards supply standby voltage (5Vsb) to the power LED header even
-- when the system is in S5/soft-off state. This can cause "power: true" to be
-- reported even though the machine appears off. This is a hardware behavior,
-- not a bug in this script.
--
-- Usage:
--   jetkvm_control atx_status.lua

print("Querying ATX state...")
local result_json = send_rpc("getATXState", '{}')

-- Parse the JSON-RPC response to extract the actual result.
-- The raw response looks like: {"id":1,"jsonrpc":"2.0","result":{"hdd":false,"power":true}}
-- We extract the "result" object to display just the power and hdd states.
local power = result_json:match('"power"%s*:%s*(true)')
local hdd   = result_json:match('"hdd"%s*:%s*(true)')

local power_state = power and "ON" or "OFF"
local hdd_state   = hdd   and "ACTIVE" or "INACTIVE"

print(string.format("Power LED: %s", power_state))
print(string.format("HDD LED:   %s", hdd_state))
print("(raw: " .. result_json .. ")")
