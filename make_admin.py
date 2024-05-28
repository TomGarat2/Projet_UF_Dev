from app import db, User, create_app

app = create_app()
app.app_context().push()

def make_admin(username):
    user = User.query.filter_by(username=username).first()
    if user:
        user.role = 'admin'
        db.session.commit()
        print(f"{username} has been granted admin privileges.")
    else:
        print(f"User {username} not found.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python make_admin.py <username>")
    else:
        make_admin(sys.argv[1])