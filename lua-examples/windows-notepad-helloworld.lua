print("Executing Lua script...")
send_windows_key()
delay(250)
send_text("notepad")
send_return()
delay(250)
delay(250)
send_text("Hello World!")
send_ctrl_a()
send_ctrl_c()
delay(250)
send_ctrl_v()
delay(250)
send_ctrl_v()

