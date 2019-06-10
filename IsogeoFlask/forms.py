from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, PasswordField, BooleanField, SubmitField
from flask_wtf.file import FileField, FileRequired
from wtforms.validators import DataRequired


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember_me = BooleanField("Remember Me")
    submit = SubmitField("Sign In")


class ImportForm(FlaskForm):
    workgroup = SelectField(label="Pick a workgroup", choices=[])
    # input_csv = FileField(label="Upload a CSV", validators=[FileRequired()])
    submit = SubmitField("OK")
