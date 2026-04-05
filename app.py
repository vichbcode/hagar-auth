import os
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, send_file, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS
from models import db, User, HagarProject, HagarField, HagarUser
import json
import io
import secrets

app = Flask(__name__)
csrf = CSRFProtect(app)
CORS(app) # Enable CORS for all routes

# --- Sécurisation de la Session ---
app.config['SECRET_KEY'] = 'dev-key-hagar-auth' # À changer en production !
app.config['SESSION_COOKIE_HTTPONLY'] = True # Empêche le vol de session via JS (XSS)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Protection anti-CSRF additionnelle
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hagar_auth.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Helper function for project security ---
def check_project_access(project):
    # Si aucun mot de passe n'est défini pour le projet, l'accès est libre
    if not project.password_hash:
        return True
    
    # Vérifie si ce projet spécifique est déverrouillé pour cette session
    session_key = f'unlocked_{project.id}'
    
    # Si on vient de soumettre le formulaire de mot de passe du projet
    if request.method == 'POST' and 'project_password' in request.form:
        password_input = request.form.get('project_password')
        if project.check_password(password_input):
            session[session_key] = True
            return True
        else:
            flash('Mot de passe du Hagar incorrect.', 'error')
            return False
            
    # Vérifie si déjà déverrouillé en session
    if session.get(session_key):
        return True
            
    return False

# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('Ce pseudo existe déjà.', 'error')
            return redirect(url_for('register'))
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template('auth/register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Pseudo ou mot de passe invalide.', 'error')
    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    # Nettoyer les sessions de projets déverrouillés lors de la déconnexion
    keys_to_remove = [key for key in session.keys() if key.startswith('unlocked_')]
    for key in keys_to_remove:
        session.pop(key)
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        new_username = request.form.get('username')
        new_password = request.form.get('password')
        if new_username:
            current_user.username = new_username
        if new_password:
            current_user.set_password(new_password)
        db.session.commit()
        flash('Profil mis à jour avec succès !', 'success')
    return render_template('auth/profile.html')

@app.route('/profile/delete', methods=['POST'])
@login_required
def delete_account():
    user = current_user
    db.session.delete(user)
    db.session.commit()
    logout_user()
    flash('Votre compte et toutes les données associées ont été supprimés définitivement.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # "Verrouillé tout le temps" : On oublie les déverrouillages dès qu'on revient au dashboard
    keys_to_remove = [key for key in session.keys() if key.startswith('unlocked_')]
    for key in keys_to_remove:
        session.pop(key)
        
    projects = current_user.projects
    return render_template('dashboard.html', projects=projects)

@app.route('/hagar/create', methods=['GET', 'POST'])
@login_required
def create_hagar():
    if request.method == 'POST':
        name = request.form.get('name')
        project_password = request.form.get('password')
        
        # Vérification : Empêcher d'utiliser le même mot de passe pour plusieurs Hagars
        if project_password:
            for existing_project in current_user.projects:
                if existing_project.password_hash and existing_project.check_password(project_password):
                    flash('Sécurité : Vous utilisez déjà ce mot de passe pour un autre Hagar. Veuillez en choisir un différent.', 'error')
                    return redirect(url_for('create_hagar'))

        # Champs dynamiques
        labels = request.form.getlist('field_label[]')
        types = request.form.getlist('field_type[]')
        
        project = HagarProject(name=name, owner_id=current_user.id)
        if project_password:
            project.set_password(project_password)
        
        db.session.add(project)
        db.session.flush() # Récupérer l'ID

        for label, ftype in zip(labels, types):
            if label and ftype:
                field = HagarField(project_id=project.id, label=label, field_type=ftype)
                db.session.add(field)
        
        db.session.commit()
        flash('Hagar créé avec succès !', 'success')
        return redirect(url_for('hagar_details', project_id=project.id))
    
    return render_template('hagar/create.html')

@app.route('/hagar/<int:project_id>', methods=['GET', 'POST'])
@login_required
def hagar_details(project_id):
    project = HagarProject.query.get_or_404(project_id)
    if project.owner_id != current_user.id:
        return "Accès non autorisé", 403
    
    if not check_project_access(project):
        return render_template('hagar/unlock.html', project=project)
    
    # Gestion de l'affichage unique du token
    display_token = not project.token_viewed
    if display_token:
        project.token_viewed = True
        db.session.commit()
        
    return render_template('hagar/details.html', project=project, display_token=display_token)

@app.route('/hagar/<int:project_id>/users', methods=['GET', 'POST'])
@login_required
def hagar_users(project_id):
    project = HagarProject.query.get_or_404(project_id)
    if project.owner_id != current_user.id:
        return "Accès non autorisé", 403
    
    if not check_project_access(project):
        return render_template('hagar/unlock.html', project=project)
    
    users = project.users
    fields = project.fields
    return render_template('hagar/users.html', project=project, users=users, fields=fields)

# --- API Endpoints ---

@csrf.exempt
@app.route('/api/hagar/<api_token>/register', methods=['POST'])
def hagar_api_register(api_token):
    project = HagarProject.query.filter_by(api_token=api_token).first_or_404()
    data = {}
    identifier = None
    password = None
    
    for field in project.fields:
        val = request.form.get(field.label)
        data[field.label] = val
        if identifier is None:
            identifier = val
        if field.field_type == 'password':
            password = val
            
    if HagarUser.query.filter_by(project_id=project.id, identifier=identifier).first():
        return jsonify({"error": "L'utilisateur existe déjà."}), 400

    h_user = HagarUser(project_id=project.id, identifier=identifier)
    if password:
        h_user.set_password(password)
    else:
        h_user.password_hash = "no_password"
    h_user.set_data(data)
    
    db.session.add(h_user)
    db.session.commit()
    return jsonify({"message": "Inscription réussie !"}), 201

@csrf.exempt
@app.route('/api/hagar/<api_token>/login', methods=['POST'])
def hagar_api_login(api_token):
    project = HagarProject.query.filter_by(api_token=api_token).first_or_404()
    identifier = request.form.get('identifier')
    password = request.form.get('password')
    
    h_user = HagarUser.query.filter_by(project_id=project.id, identifier=identifier).first()
    if h_user:
        if h_user.password_hash == "no_password":
            return jsonify({"message": "Connexion réussie !", "user_data": h_user.get_data()}), 200
        elif password and h_user.check_password(password):
            return jsonify({"message": "Connexion réussie !", "user_data": h_user.get_data()}), 200
    
    return jsonify({"error": "Identifiants invalides."}), 401

@app.route('/hagar/<int:project_id>/download/<type>')
@login_required
def download_file(project_id, type):
    project = HagarProject.query.get_or_404(project_id)
    if project.owner_id != current_user.id:
        return "Accès non autorisé", 403
    
    if project.password_hash and not session.get(f'unlocked_{project.id}'):
        return "Hagar verrouillé.", 403

    if type == 'signup':
        filename = "inscription.html"
        content = render_template('hagar/gen_signup.html', project=project)
    elif type == 'login':
        filename = "connexion.html"
        content = render_template('hagar/gen_login.html', project=project)
    elif type == 'config':
        filename = "hagar_config.js"
        content = f"const HAGAR_CONFIG = {{\n  api_token: '{project.api_token}',\n  base_url: '{request.host_url.rstrip('/')}'\n}};"
    else:
        return "Type de fichier invalide.", 400

    return send_file(io.BytesIO(content.encode('utf-8')), mimetype='text/plain', as_attachment=True, download_name=filename)

@app.route('/hagar/<int:project_id>/delete', methods=['POST'])
@login_required
def delete_hagar(project_id):
    project = HagarProject.query.get_or_404(project_id)
    if project.owner_id != current_user.id:
        return "Accès non autorisé", 403
    
    if project.password_hash and not session.get(f'unlocked_{project.id}'):
        return "Hagar verrouillé.", 403

    db.session.delete(project)
    db.session.commit()
    flash(f'Le Hagar "{project.name}" a été supprimé.', 'success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Migration manuelle pour ajouter les colonnes si elles manquent
        try:
            db.session.execute(db.text("ALTER TABLE hagar_project ADD COLUMN password_hash VARCHAR(256)"))
            db.session.commit()
        except:
            db.session.rollback()

        try:
            db.session.execute(db.text("ALTER TABLE hagar_project ADD COLUMN token_viewed BOOLEAN DEFAULT 0"))
            db.session.commit()
        except:
            db.session.rollback()
            
    app.run(debug=True)
