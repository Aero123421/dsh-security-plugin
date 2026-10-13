# INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField, FileRequired
from wtforms import EmailField, IntegerField, PasswordField, StringField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, NumberRange

ALLOWED = ["pdf", "png", "jpg", "txt", "md"]


class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired(), Email(), Length(max=254)])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=128)])


class UploadForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(max=200)])
    notes = TextAreaField("Notes", validators=[Length(max=10_000)])
    file = FileField("File", validators=[FileRequired(), FileAllowed(ALLOWED, "Unsupported file type")])


class ShareForm(FlaskForm):
    days = IntegerField("Valid for (days)", default=7, validators=[NumberRange(min=1, max=30)])
