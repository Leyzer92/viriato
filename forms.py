from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length
import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError

class LoginForm(FlaskForm):
    email_or_username = StringField('Correo o Usuario', validators=[DataRequired(), Length(min=4, max=150)])
    password = PasswordField('Contraseña', validators=[DataRequired(), Length(min=6, max=128)])
    remember = BooleanField('Recordarme')
    submit = SubmitField('Iniciar Sesión')
    
def password_complexity_check(form, field):
    password = field.data
    if len(password) < 8:
        raise ValidationError('La contraseña debe tener al menos 8 caracteres.')
    if not re.search(r'[A-Z]', password):
        raise ValidationError('La contraseña debe tener al menos una letra mayúscula.')
    if not re.search(r'[a-z]', password):
        raise ValidationError('La contraseña debe tener al menos una letra minúscula.')
    if not re.search(r'\d', password):
        raise ValidationError('La contraseña debe tener al menos un número.')
    if not re.search(r'[@$!%*?&]', password):
        raise ValidationError('La contraseña debe tener al menos un carácter especial (@, $, !, %, *, ?, &).')

class RegistrationForm(FlaskForm):
    username = StringField('Nombre de Usuario', validators=[DataRequired(), Length(min=4, max=150)])
    email = StringField('Correo Electrónico', validators=[DataRequired(), Email(), Length(max=150)])
    password = PasswordField('Contraseña', validators=[DataRequired(), password_complexity_check])
    # Puedes agregar un campo para confirmar contraseña si lo deseas:
    # confirm_password = PasswordField('Confirmar Contraseña', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Registrarse')

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo

class RequestResetForm(FlaskForm):
    email = StringField('Correo Electrónico', validators=[DataRequired(), Email(), Length(max=150)])
    submit = SubmitField('Enviar enlace de restablecimiento')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Nueva Contraseña', validators=[DataRequired(), Length(min=6, max=128)])
    confirm_password = PasswordField('Confirmar Contraseña', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Restablecer Contraseña')

