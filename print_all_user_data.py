from login_server import app, db, User

def print_users_table():
    with app.app_context():
        users = User.query.all()
        print(f"{'Username':<20}{'Email':<30}{'Password':<20}{'high scores':<20}")
        print("-" * 70)
        for user in users:
            print(f"{user.username:<20}{user.email:<30}{user.password_hash:<20}{user.highscores:<20}")

if __name__ == "__main__":
    print_users_table()
