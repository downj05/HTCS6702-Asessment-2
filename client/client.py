import commands
import traceback

if __name__ == '__main__':
    session_key = commands.login_screen()
    commands.help()
    while True:  # Command loop
        cmd = input(":").lower().split(' ')  # Lower command capitalization and separate by spaces

        try:
            if cmd[0] == 'list':
                commands.list_table(session_id=session_key, table=cmd[1], amount=int(cmd[2]))

            elif cmd[0] == 'add':
                if cmd[1] == 'user':
                    commands.add_user(session_key)
                elif cmd[1] == 'service':
                    commands.add_service(session_key)
                elif cmd[1] == 'subscription':
                    commands.add_subscription(session_key)

            elif cmd[0] == 'info':
                commands.info(session_key)

            elif cmd[0] == 'help':
                commands.help()

            else:
                print("Command does not exist.")
        except IndexError:
            print("Not enough command arguments")
        except Exception as e:
            print("Error!")
            traceback.print_exc()