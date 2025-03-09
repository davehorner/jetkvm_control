print("[DEBUG] Pressing Cmd and Space")

send_key_combinations({
    { modifier = 0x08, keys = { 44 }, hold_keys = true, hold_modifiers = true, hold = 100 } -- Hold Cmd, Press Space
})

print("[DEBUG] Releasing Cmd and Space")
send_key_combinations({
    { modifier = 0x00, keys = { 44 }, hold_keys = false, hold_modifiers = false, hold = 100, wait = 500 } -- Release Cmd+Space
})

