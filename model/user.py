from datetime import datetime
from flask_login import UserMixin
from . import db, bcrypt

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

    # Optional helper method
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

def create_user(username, password, is_admin=False):
    """Create a new user with a hashed password."""
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password=hashed_password, is_admin=is_admin)
    db.session.add(new_user)
    db.session.commit()
    return new_user

def get_user_by_username(username):
    """Retrieve a user by username."""
    return User.query.filter_by(username=username).first()

def get_user_by_id(user_id):
    """Retrieve a user by ID."""
    return User.query.get(int(user_id))

def update_user(user_id, **kwargs):
    """Update user fields dynamically."""
    user = User.query.get(user_id)
    if not user:
        return None

    for key, value in kwargs.items():
        if hasattr(user, key):
            setattr(user, key, value)

    db.session.commit()
    return user

def delete_user(user_id):
    """Delete a user by ID."""
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return True
    return False