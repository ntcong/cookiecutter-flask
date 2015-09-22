# -*- coding: utf-8 -*-
from flask_wtf import Form
from wtforms import TextField, PasswordField
from wtforms.validators import DataRequired, Email, EqualTo, Length

from {{cookiecutter.app_name}}.models.user import User


class RegisterForm(Form):
    username = TextField('Username',
                         validators=[DataRequired(), Length(min=3,
                                                            max=25)])
    email = TextField('Email',
                      validators=[DataRequired(), Email(), Length(min=6,
                                                                  max=40)])
    password = PasswordField('Password',
                             validators=[DataRequired(), Length(min=6,
                                                                max=40)])
    confirm = PasswordField('Verify password',
                            [DataRequired(),
                             EqualTo('password',
                                     message='Passwords must match')])

    def __init__(self, *args, **kwargs):
        super(RegisterForm, self).__init__(*args, **kwargs)
        self.user = None

    def validate(self):
        initial_validation = super(RegisterForm, self).validate()
        if not initial_validation:
            return False
        user = User.query.filter_by(username=self.username.data).first()
        if user:
            self.username.errors.append("Username already registered")
            return False
        user = User.query.filter_by(email=self.email.data).first()
        if user:
            self.email.errors.append("Email already registered")
            return False
        return True


class LoginForm(Form):
    username = TextField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

    def __init__(self, *args, **kwargs):
        super(LoginForm, self).__init__(*args, **kwargs)
        self.user = None

    def validate(self):
        initial_validation = super(LoginForm, self).validate()
        if not initial_validation:
            return False

        self.user = User.query.filter_by(username=self.username.data).first()
        if not self.user:
            self.username.errors.append('Unknown username')
            return False

        if not self.user.check_password(self.password.data):
            self.password.errors.append('Invalid password')
            return False

        if not self.user.active:
            self.username.errors.append('User not activated')
            return False
        return True
