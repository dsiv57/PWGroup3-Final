from datetime import datetime
from . import db
from model.user import User

class Log(db.Model):
    __tablename__ = 'logs'

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(), nullable=False)

    is_error = db.Column(db.Boolean, default=False, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    user = db.relationship('User', backref='logs')

    def __repr__(self):
        return f"<Log {self.type} from {self.ip} at {self.timestamp}>"

def create_log(ip, log_type, user=None, is_error=False):
    """Create a new log entry. 'user' can be a User object or None."""
    user_id = user.id if user else None
    log = Log(ip=ip, type=log_type, user_id=user_id, is_error=is_error)
    db.session.add(log)
    db.session.commit()
    return log

def get_all_logs():
    """Return all logs, newest first."""
    return Log.query.order_by(Log.timestamp.desc()).all()

def get_logs_by_user(user_id):
    """Return all logs for a specific user."""
    return Log.query.filter_by(user_id=user_id).order_by(Log.timestamp.desc()).all()

def get_error_logs():
    """Return only logs marked as errors, newest first."""
    return Log.query.filter_by(is_error=True).order_by(Log.timestamp.desc()).all()

def delete_log(log_id):
    """Delete a log by ID."""
    log = Log.query.get(log_id)
    if log:
        db.session.delete(log)
        db.session.commit()
        return True
    return False