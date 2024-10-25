from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    _password_hash = db.Column(db.String)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    # Relationships
    recipes = db.relationship('Recipe', backref='user', lazy=True, cascade="all, delete-orphan")

    # Serialization rules
    serialize_rules = ('-_password_hash', '-recipes.user')

    def __init__(self, **kwargs):
        # Handle password_hash if it's provided in kwargs
        password = kwargs.pop('password_hash', None)
        super().__init__(**kwargs)
        if password:
            self.password_hash = password

    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed.')

    @password_hash.setter
    def password_hash(self, password):
        if password is None:
            raise ValueError("Password can't be blank")
        password_hash = bcrypt.generate_password_hash(
            password.encode('utf-8')
        )
        self._password_hash = password_hash.decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(
            self._password_hash, password.encode('utf-8')
        )

    @validates('username')
    def validate_username(self, key, username):
        if not username:
            raise ValueError("Username must be provided")
        return username

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)
    
    # Foreign key
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    # Serialization rules
    serialize_rules = ('-user.recipes',)

    @validates('title')
    def validate_title(self, key, title):
        if not title:
            raise ValueError("Title must be provided")
        return title

    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if not instructions:
            raise ValueError("Instructions must be provided")
        if len(instructions) < 50:
            raise ValueError("Instructions must be at least 50 characters long")
        return instructions

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.user_id:
            # Create a default user if none is provided
            default_user = User.query.first()
            if not default_user:
                default_user = User(username="default_user", password_hash="password123")
                db.session.add(default_user)
                db.session.commit()
            self.user_id = default_user.id