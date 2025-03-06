print("Executing Lua script...")
-- for i = 1, 10 do
   send_key_combinations({
       { modifier = 0x04, keys = {0x3D}, hold = 100, wait = 1000 }, -- Alt+F4
       { modifier = 0, keys = {0x4F}, hold = 100, wait = 550 }, -- Right arrow
    -- { modifier = 0, keys = {0x4F}, hold = 100, wait = 50 }, -- Right arrow again (cancel button)
       { modifier = 0, keys = {0x28}, hold = 100, wait = 50 }  -- Return (Enter)
   })
-- end
