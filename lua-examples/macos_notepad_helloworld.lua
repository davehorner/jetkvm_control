-- Function to send key combinations
function send_key_combinations(combos)
    for _, combo in ipairs(combos) do
        -- Here, you would call the RPC function to send key events.
        -- Replace this with your actual implementation.
        print(string.format(
            "[DEBUG] Sending Key Combo -> Modifier: 0x%X, Keys: %s, Hold: %s, Wait: %s, Instant Release: %s",
            combo.modifier or 0,
            table.concat(combo.keys or {}, ", "),
            tostring(combo.hold or "None"),
            tostring(combo.wait or "None"),
            tostring(combo.instant_release or "false")
        ))
    end
end

-- Open TextEdit on macOS
print("[DEBUG] Opening TextEdit")
os.execute("open -a TextEdit")

-- Wait a bit for the app to open
print("[DEBUG] Waiting for TextEdit to launch...")
send_key_combinations({ { wait = 2000 } })

-- Type "Hello, World!"
print("[DEBUG] Typing 'Hello, World!'")
send_key_combinations({
    { keys = { 0x0B }, hold = 50 }, -- H
    { keys = { 0x08 }, hold = 50 }, -- e
    { keys = { 0x0F }, hold = 50 }, -- l
    { keys = { 0x0F }, hold = 50 }, -- l
    { keys = { 0x12 }, hold = 50 }, -- o
    { keys = { 0x2C }, hold = 50 }, -- ,
    { keys = { 0x31 }, hold = 50 }, -- Space
    { keys = { 0x0D }, hold = 50 }, -- W
    { keys = { 0x12 }, hold = 50 }, -- o
    { keys = { 0x15 }, hold = 50 }, -- r
    { keys = { 0x0F }, hold = 50 }, -- l
    { keys = { 0x02 }, hold = 50 }, -- d
    { keys = { 0x29 }, hold = 50 }, -- !
})

-- Save the file (Cmd+S)
print("[DEBUG] Saving file")
send_key_combinations({
    { modifier = 0x10, keys = { 0x01 }, hold = 200, wait = 1000 } -- Cmd+S
})

-- Wait for save dialog
print("[DEBUG] Waiting for Save dialog...")
send_key_combinations({ { wait = 2000 } })

-- Type filename "HelloWorld"
print("[DEBUG] Typing filename 'HelloWorld'")
send_key_combinations({
    { keys = { 0x0B }, hold = 50 }, -- H
    { keys = { 0x08 }, hold = 50 }, -- e
    { keys = { 0x0F }, hold = 50 }, -- l
    { keys = { 0x0F }, hold = 50 }, -- l
    { keys = { 0x12 }, hold = 50 }, -- o
    { keys = { 0x0D }, hold = 50 }, -- W
    { keys = { 0x12 }, hold = 50 }, -- o
    { keys = { 0x15 }, hold = 50 }, -- r
    { keys = { 0x0F }, hold = 50 }, -- l
    { keys = { 0x02 }, hold = 50 }  -- d
})

-- Save file (Enter)
print("[DEBUG] Pressing Enter to save")
send_key_combinations({ { keys = { 0x24 }, hold = 100 } }) -- Enter

-- Done
print("[DEBUG] Done!")

