print("[DEBUG] Pressing Cmd Twice for Siri")

send_key_combinations({
    { modifier = 0x08, keys = {}, hold_keys = true, hold_modifiers = true, hold = 100 } -- Press Cmd
})

send_key_combinations({
    { modifier = 0x00, keys = {}, hold_keys = false, hold_modifiers = false, hold = 100, wait = 200 } -- Release Cmd
})

send_key_combinations({
    { modifier = 0x08, keys = {}, hold_keys = true, hold_modifiers = true, hold = 100, wait = 50 } -- Press Cmd again quickly
})

send_key_combinations({
    { modifier = 0x00, keys = {}, hold_keys = false, hold_modifiers = false, hold = 100, wait = 500 } -- Release Cmd again
})

print("[DEBUG] Siri should be open now!")

