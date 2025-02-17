import os
from datetime import timedelta, datetime

from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
    UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask_migrate import Migrate

# -------------------------------------------------------------------
# App Configurations
# -------------------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'tusecretokey'  # Cambia esta clave en producción
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=7)
from itsdangerous import URLSafeTimedSerializer
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Configuración para subida de archivos
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Configuración de correo
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'academiaviriato@gmail.com'
app.config['MAIL_PASSWORD'] = 'vcgm aelz jmvy hrte'

# Initialize Extensions
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

# -------------------------------------------------------------------
# Models
# -------------------------------------------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_approved = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    category = db.Column(db.String(50), nullable=False, default='Noticias', server_default='Noticias')
    subforum = db.Column(db.String(50), nullable=True)
    edited_at = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='post', lazy=True, cascade="all, delete-orphan")
    user = db.relationship('User', backref=db.backref('posts', lazy=True))

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('comments', lazy=True))

# -------------------------------------------------------------------
# General Routes
# -------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/preparaciones')
def preparaciones():
    return render_template('preparaciones.html')

@app.route('/pago')
@login_required
def pago():
    return render_template('pago.html')

@app.route('/suboficial')
def suboficial():
    return render_template('suboficial.html')


# -------------------------------------------------------------------
# Authentication Routes
# -------------------------------------------------------------------
from forms import LoginForm, RegistrationForm, RequestResetForm, ResetPasswordForm

from forms import LoginForm, RegistrationForm, RequestResetForm, ResetPasswordForm

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Verificar si el usuario ya existe
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('El usuario o email ya existe, por favor elige otro.', 'danger')
            return redirect(url_for('register'))
        
        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password, method='pbkdf2:sha256')
        )
        db.session.add(new_user)
        db.session.commit()
        
        # Generar token para confirmar el registro y construir la URL de confirmación
        token = s.dumps(new_user.email, salt='email-confirm-salt')
        confirm_url = url_for('confirm_email', token=token, _external=True)
        
        # Enviar correo de confirmación de registro
        msg = Message("Confirma tu registro en la web",
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[email])
        msg.body = ("¡Gracias por registrarte en nuestra web!\n\n"
                    "Para confirmar tu registro, por favor haz clic en el siguiente enlace:\n"
                    "{}\n\n"
                    "Si no solicitaste este registro, ignora este mensaje.".format(confirm_url))
        mail.send(msg)
        
        flash('Registro exitoso, por favor revisa tu correo para confirmar tu registro.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm-salt', max_age=3600)
    except Exception:
        flash('El enlace de confirmación es inválido o ha caducado.', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.filter_by(email=email).first_or_404()
    # Aquí puedes marcar al usuario como confirmado, por ejemplo:
    user.is_confirmed = True  # Asegúrate de tener este campo en tu modelo User
    db.session.commit()
    flash('Tu cuenta ha sido confirmada. ¡Ahora puedes iniciar sesión!', 'success')
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    register_form = RegistrationForm()
    if form.validate_on_submit():
        email_or_username = form.email_or_username.data.strip()
        password = form.password.data
        remember = form.remember.data
        user = User.query.filter((User.email == email_or_username) | (User.username == email_or_username)).first()
        if not user or not check_password_hash(user.password, password):
            flash('Credenciales inválidas. Inténtalo de nuevo.', 'danger')
            return redirect(url_for('login'))
        login_user(user, remember=remember)
        flash('Has iniciado sesión correctamente.', 'success')
        return redirect(url_for('index'))
    if form.errors:
        flash('Por favor, revisa los errores en el formulario.', 'warning')
    return render_template('login.html', form=form, register_form=register_form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión.', 'success')
    return redirect(url_for('index'))
# Panel de usuario: Visualización del perfil
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

# Ruta para cambiar el correo electrónico
@app.route('/profile/change_email', methods=['GET', 'POST'])
@login_required
def change_email():
    if request.method == 'POST':
        new_email = request.form.get('new_email')
        # Verificar que el nuevo correo no esté ya registrado
        if User.query.filter_by(email=new_email).first():
            flash('El correo electrónico ya está en uso.', 'danger')
        else:
            current_user.email = new_email
            db.session.commit()
            flash('Correo electrónico actualizado correctamente.', 'success')
            return redirect(url_for('profile'))
    return render_template('change_email.html', user=current_user)

# Ruta para cambiar la contraseña
@app.route('/profile/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not check_password_hash(current_user.password, current_password):
            flash('La contraseña actual es incorrecta.', 'danger')
        elif new_password != confirm_password:
            flash('La nueva contraseña y la confirmación no coinciden.', 'danger')
        else:
            current_user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
            db.session.commit()
            flash('Contraseña actualizada correctamente.', 'success')
            return redirect(url_for('profile'))
    return render_template('change_password.html', user=current_user)

# -------------------------------------------------------------------
# Password Reset Routes
# -------------------------------------------------------------------
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password_request():
    form = RequestResetForm()
    if form.validate_on_submit():
        email = form.email.data.strip()
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(user.email, salt='password-reset-salt')
            reset_link = url_for('reset_password_token', token=token, _external=True)
            msg = Message('Restablece tu contraseña',
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[user.email])
            msg.body = f'Para restablecer tu contraseña, visita el siguiente enlace:\n{reset_link}\n\nSi no solicitaste este cambio, ignora este mensaje.'
            mail.send(msg)
            flash('Se ha enviado un enlace de restablecimiento a tu correo.', 'info')
        else:
            flash('No se encontró un usuario con ese correo.', 'warning')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except Exception:
        flash('El enlace de restablecimiento es inválido o ha caducado.', 'danger')
        return redirect(url_for('reset_password_request'))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
            db.session.commit()
            flash('Tu contraseña ha sido restablecida. Ahora puedes iniciar sesión.', 'success')
            return redirect(url_for('login'))
        else:
            flash('No se encontró un usuario con ese correo.', 'danger')
            return redirect(url_for('reset_password_request'))
    return render_template('reset_password_token.html', form=form)

# -------------------------------------------------------------------
# User Account Management Routes
# -------------------------------------------------------------------
@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user = current_user
    logout_user()
    db.session.delete(user)
    db.session.commit()
    flash("Tu cuenta ha sido eliminada.", "success")
    return redirect(url_for('index'))

# -------------------------------------------------------------------
# Forum Routes
# -------------------------------------------------------------------
@app.route('/forum')
@login_required
def forum():
    category = request.args.get('category', 'Noticias')
    subforum = request.args.get('subforum')
    search_query = request.args.get('q', '')
    page = request.args.get('page', 1, type=int)
    
    posts_query = Post.query.filter(Post.category == category)
    if subforum:
        posts_query = posts_query.filter(Post.subforum == subforum)
    if search_query:
        posts_query = posts_query.filter(
            Post.title.contains(search_query) | Post.content.contains(search_query)
        )
    posts = posts_query.order_by(Post.timestamp.desc()).paginate(page=page, per_page=5)
    latest_posts = Post.query.order_by(Post.timestamp.desc()).limit(5).all()
    
    return render_template('forum.html', posts=posts, latest_posts=latest_posts,
                           search_query=search_query, current_category=category, current_subforum=subforum)

@app.route('/forum/new', methods=['GET', 'POST'])
@login_required
def new_post():
    category = request.args.get('category', 'Noticias')
    subforum = request.args.get('subforum')
    
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        # Permitir sobrescribir categoría y subforo mediante el formulario
        category = request.form.get('category', category)
        subforum = request.form.get('subforum', subforum)
        
        if not title or not content:
            flash("El título y el contenido son obligatorios.", "danger")
            return redirect(url_for('new_post', category=category, subforum=subforum))
        
        post = Post(
            title=title,
            content=content,
            user_id=current_user.id,
            category=category,
            subforum=subforum
        )
        db.session.add(post)
        db.session.commit()
        flash("Publicación creada.", "success")
        return redirect(url_for('forum', category=category, subforum=subforum))
    return render_template('new_post.html', category=category, subforum=subforum)

@app.route('/post/<int:post_id>')
@login_required
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('view_post.html', post=post)

@app.route('/post/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if not (current_user.is_admin or post.user_id == current_user.id):
        flash("No tienes permisos para editar este post.", "danger")
        return redirect(url_for('forum'))
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        if not title or not content:
            flash("El título y el contenido no pueden estar vacíos.", "danger")
            return redirect(url_for('edit_post', post_id=post_id))
        post.title = title
        post.content = content
        post.edited_at = datetime.utcnow()
        db.session.commit()
        flash("Post actualizado correctamente.", "success")
        return redirect(url_for('forum', category=post.category, subforum=post.subforum))
    return render_template('edit_post.html', post=post)

@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if not (current_user.is_admin or post.user_id == current_user.id):
        flash("No tienes permisos para eliminar este post.", "danger")
        return redirect(url_for('forum'))
    db.session.delete(post)
    db.session.commit()
    flash("Post eliminado correctamente.", "success")
    return redirect(url_for('forum', category=post.category, subforum=post.subforum))

@app.route('/forum/<int:post_id>/reply', methods=['GET', 'POST'])
@login_required
def reply_post(post_id):
    if not (current_user.is_admin or current_user.is_approved):
        flash("No tienes permisos para acceder al foro.", "warning")
        return redirect(url_for('index'))
    post = Post.query.get_or_404(post_id)
    if request.method == 'POST':
        content = request.form.get('content')
        if not content:
            flash("El mensaje no puede estar vacío.", "danger")
            return redirect(url_for('reply_post', post_id=post_id))
        comment = Comment(content=content, post_id=post.id, user_id=current_user.id)
        db.session.add(comment)
        db.session.commit()
        flash("Respuesta publicada.", "success")
        return redirect(url_for('forum'))
    return render_template('reply_post.html', post=post)

@app.route('/comment/<int:comment_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if not (current_user.is_admin or comment.user_id == current_user.id):
        flash("No tienes permisos para editar este comentario.", "danger")
        return redirect(url_for('forum'))
    if request.method == 'POST':
        new_content = request.form.get('content')
        if not new_content:
            flash("El contenido no puede estar vacío.", "danger")
            return redirect(url_for('edit_comment', comment_id=comment_id))
        comment.content = new_content
        db.session.commit()
        flash("Comentario actualizado.", "success")
        return redirect(url_for('forum'))
    return render_template('edit_comment.html', comment=comment)

@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if not (current_user.is_admin or comment.user_id == current_user.id):
        flash("No tienes permisos para eliminar este comentario.", "danger")
        return redirect(url_for('forum'))
    db.session.delete(comment)
    db.session.commit()
    flash("El comentario ha sido eliminado.", "success")
    return redirect(url_for('forum'))

# -------------------------------------------------------------------
# Admin Routes
# -------------------------------------------------------------------
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash("No tienes permisos para acceder a esta sección.", "danger")
        return redirect(url_for('index'))
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/disapprove_user/<int:user_id>', methods=['POST'])
@login_required
def disapprove_user(user_id):
    if not getattr(current_user, 'is_admin', False):
        flash("No tienes permisos para realizar esta acción.", "danger")
        return redirect(url_for('index'))
    user = User.query.get(user_id)
    if not user:
        flash("Usuario no encontrado.", "danger")
        return redirect(url_for('admin_dashboard'))
    user.is_approved = False
    db.session.commit()
    flash("Usuario desaprobado correctamente.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash("No tienes permisos para realizar esta acción.", "danger")
        return redirect(url_for('index'))
    user = User.query.get(user_id)
    if not user:
        flash("Usuario no encontrado.", "danger")
        return redirect(url_for('admin_dashboard'))
    db.session.delete(user)
    db.session.commit()
    flash("Usuario eliminado correctamente.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/approve_user/<int:user_id>', methods=['POST'])
@login_required
def approve_user(user_id):
    if not current_user.is_admin:
        flash("No tienes permisos para realizar esta acción.", "danger")
        return redirect(url_for('index'))
    user = User.query.get(user_id)
    if not user:
        flash("Usuario no encontrado.", "danger")
        return redirect(url_for('admin_dashboard'))
    user.is_approved = True
    db.session.commit()
    flash(f"Usuario {user.username} aprobado correctamente.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin_upload', methods=['GET', 'POST'])
@login_required
def admin_upload():
    if not current_user.is_admin:
        flash("No tienes permisos para acceder a esta sección.", "danger")
        return redirect(url_for('index'))
    if request.method == 'POST':
        subject = request.form.get('subject')
        folder = request.form.get('folder')
        file = request.files.get('file')
        
        if not subject or not folder:
            flash('Debes seleccionar la materia y el temario.', 'danger')
            return redirect(request.url)
        if not file or file.filename == '':
            flash('No se seleccionó ningún archivo.', 'danger')
            return redirect(request.url)
        
        destination = os.path.join(app.root_path, 'static', 'downloads', subject, folder)
        os.makedirs(destination, exist_ok=True)
        
        filename = secure_filename(file.filename)
        file.save(os.path.join(destination, filename))
        flash('Archivo subido exitosamente.', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_upload.html')

@app.route('/admin_files')
@login_required
def admin_files():
    if not current_user.is_admin:
        flash("No tienes permisos para acceder a esta sección.", "danger")
        return redirect(url_for('index'))
    download_folder = os.path.join(app.root_path, 'static', 'downloads')
    files = []
    for root, _, file_list in os.walk(download_folder):
        for f in file_list:
            relative_path = os.path.relpath(os.path.join(root, f), download_folder)
            files.append(relative_path)
    return render_template('admin_files.html', files=files)

@app.route('/delete_file/<path:filename>', methods=['POST'])
@login_required
def delete_file(filename):
    if not current_user.is_admin:
        flash("No tienes permisos para realizar esta acción.", "danger")
        return redirect(url_for('index'))
    download_folder = os.path.join(app.root_path, 'static', 'downloads')
    file_path = os.path.join(download_folder, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        flash("Archivo eliminado exitosamente.", "success")
    else:
        flash("Archivo no encontrado.", "danger")
    return redirect(url_for('admin_files'))

@app.route('/download/<subject>/<folder>')
@login_required
def download_page(subject, folder):
    directory = os.path.join(app.root_path, 'static', 'downloads', subject, folder)
    if not os.path.exists(directory):
        flash("El temario solicitado no existe.", "danger")
        return redirect(url_for('content'))
    files = os.listdir(directory)
    return render_template('download_page.html', subject=subject, folder=folder, files=files)

@app.route('/content')
@login_required
def content():
    if not current_user.is_approved:
        flash("Tu cuenta aún no ha sido aprobada para acceder al contenido. Contacta al administrador.", "warning")
        return redirect(url_for('index'))
    return render_template('content.html')

@app.route('/create_admin')
def create_admin():
    # Ruta solo para desarrollo; ¡no dejar en producción!
    if User.query.filter_by(username='amatrab').first():
        return "El usuario admin ya existe."
    admin = User(
        username='amatrab',
        email='alejandrogmateosr@gmail.com',
        password=generate_password_hash('mamon10', method='pbkdf2:sha256'),
        is_admin=True,
        is_approved=True
    )
    db.session.add(admin)
    db.session.commit()
    return "Usuario admin creado exitosamente."

# -------------------------------------------------------------------
# Run Application
# -------------------------------------------------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
