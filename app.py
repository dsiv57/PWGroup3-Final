from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from model import db, bcrypt
from model.user import User, create_user, get_user_by_username, get_user_by_id
from model.log import Log, create_log
from model.analyzer import SecurityAnalyzer
from model.validator import InputValidator
from model.password_validator import PasswordValidator
import os

app = Flask(__name__)
app.secret_key = 'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef12345678'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
bcrypt.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Devi effettuare il login per accedere a questa pagina.'


@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(user_id)


def ensure_admin_user():
    admin_username = os.getenv('ADMIN_USERNAME', 'admin')
    admin_password = os.getenv('ADMIN_PASSWORD', 'Admin123!')
    
    admin = get_user_by_username(admin_username)
    if not admin:
        try:
            create_user(admin_username, admin_password, is_admin=True)
            print(f"Utente admin '{admin_username}' creato automaticamente")
        except Exception as e:
            print(f"Errore creazione admin: {e}")
    else:
        print(f"Utente admin '{admin_username}' già esistente")


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        validation_username = InputValidator.validate_sql_only(username, 'username')
        
        if not validation_username['is_safe']:
            create_log(
                ip=request.remote_addr,
                log_type=f"MALICIOUS_INPUT_{validation_username['attack_type']}",
                user=None,
                is_error=True
            )
            flash('Input sospetto rilevato. Tentativo bloccato per motivi di sicurezza.', 'danger')
            return render_template('login.html')

        user = get_user_by_username(username)

        if user and user.check_password(password):
            login_user(user)
            
            create_log(
                ip=request.remote_addr,
                log_type="LOGIN_SUCCESS",
                user=user,
                is_error=False
            )
            
            flash('Login effettuato con successo!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('home'))
        else:
            create_log(
                ip=request.remote_addr,
                log_type="LOGIN_FAILED",
                user=None,
                is_error=True
            )
            
            flash('Username o password non corretti.', 'error')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        validation_username = InputValidator.validate_sql_only(username, 'username')
        
        if not validation_username['is_safe']:
            create_log(
                ip=request.remote_addr,
                log_type=f"MALICIOUS_INPUT_{validation_username['attack_type']}",
                user=None,
                is_error=True
            )
            flash('Input sospetto rilevato. Tentativo bloccato per motivi di sicurezza.', 'danger')
            return render_template('register.html')

        if not username or not password:
            flash('Tutti i campi sono obbligatori.', 'error')
            return render_template('register.html')

        if password != confirm_password:
            flash('Le password non corrispondono.', 'error')
            return render_template('register.html')

        if get_user_by_username(username):
            flash('Username già esistente.', 'error')
            return render_template('register.html')

        password_validation = PasswordValidator.validate_strength(password, username)
        if not password_validation['is_strong']:
            flash('La password non soddisfa i requisiti di sicurezza.', 'error')
            return render_template('register.html')

        new_user = create_user(username, password)

        create_log(
            ip=request.remote_addr,
            log_type="REGISTER_SUCCESS",
            user=new_user,
            is_error=False
        )
        
        flash('Registrazione completata!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/home')
@login_required
def home():
    create_log(
        ip=request.remote_addr,
        log_type="PAGE_ACCESS",
        user=current_user,
        is_error=False
    )
    
    return render_template('home.html', username=current_user.username)


@app.route('/logout')
@login_required
def logout():
    create_log(
        ip=request.remote_addr,
        log_type="LOGOUT",
        user=current_user,
        is_error=False
    )
    
    logout_user()
    flash('Logout effettuato con successo!', 'success')
    return redirect(url_for('login'))


@app.route('/logs')
@login_required
def logs():

    if not getattr(current_user, 'is_admin', False):
        flash('Accesso negato: sezione riservata agli amministratori.', 'error')
        return redirect(url_for('home'))

    if not request.args:
        create_log(
            ip=request.remote_addr,
            log_type="PAGE_ACCESS_LOGS",
            user=current_user,
            is_error=False
        )

    filter_type = request.args.get('type', '')
    filter_ip = request.args.get('ip', '')
    filter_user = request.args.get('user', '')
    filter_error = request.args.get('error', '')
    filter_date = request.args.get('date', '')
    
    query = Log.query

    if filter_type:
        query = query.filter(Log.type.like(f'%{filter_type}%'))
    
    if filter_ip:
        query = query.filter(Log.ip.like(f'%{filter_ip}%'))
    
    if filter_user:
        query = query.join(User).filter(User.username.like(f'%{filter_user}%'))
    
    if filter_error == 'true':
        query = query.filter(Log.is_error == True)
    elif filter_error == 'false':
        query = query.filter(Log.is_error == False)
    
    if filter_date:
        from datetime import datetime, timedelta
        try:
            target_date = datetime.strptime(filter_date, '%Y-%m-%d')
            next_day = target_date + timedelta(days=1)
            query = query.filter(Log.timestamp >= target_date, Log.timestamp < next_day)
        except ValueError:
            pass 

    all_logs = query.order_by(Log.timestamp.desc()).limit(200).all()

    alerts = SecurityAnalyzer.get_all_alerts()

    total_logs = len(all_logs)
    error_count = sum(1 for log in all_logs if log.is_error)
    login_success = sum(1 for log in all_logs if log.type == "LOGIN_SUCCESS")
    login_failed = sum(1 for log in all_logs if log.type == "LOGIN_FAILED")
    
    stats = {
        'total': total_logs,
        'errors': error_count,
        'login_success': login_success,
        'login_failed': login_failed
    }

    all_log_types = db.session.query(Log.type).distinct().all()
    log_types = sorted([t[0] for t in all_log_types])

    all_ips = db.session.query(Log.ip).distinct().limit(50).all()
    unique_ips = sorted([ip[0] for ip in all_ips])
    
    # Converti i log in dizionari JSON-serializzabili per i grafici
    logs_json = []
    for log in all_logs:
        logs_json.append({
            'id': log.id,
            'timestamp': log.timestamp.isoformat(),
            'type': log.type,
            'ip': log.ip,
            'is_error': log.is_error,
            'user': log.user.username if log.user else None
        })
    
    # Calcola conteggio per tipo di log per la legenda
    from collections import Counter
    log_type_counts = Counter(log.type for log in all_logs)
    
    return render_template('logs.html', 
                         logs=all_logs,
                         logs_json=logs_json,
                         log_type_counts=log_type_counts,
                         stats=stats, 
                         alerts=alerts,
                         log_types=log_types,
                         unique_ips=unique_ips,
                         filters={
                             'type': filter_type,
                             'ip': filter_ip,
                             'user': filter_user,
                             'error': filter_error,
                             'date': filter_date
                         })


@app.route('/account')
@login_required
def account():
    return render_template('account.html')


@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if not current_password or not new_password or not confirm_password:
        flash('Tutti i campi sono obbligatori.', 'error')
        return redirect(url_for('account'))

    if not current_user.check_password(current_password):
        create_log(
            ip=request.remote_addr,
            log_type="PASSWORD_CHANGE_FAILED",
            user=current_user,
            is_error=True
        )
        flash('Password attuale non corretta.', 'error')
        return redirect(url_for('account'))

    if new_password != confirm_password:
        flash('Le nuove password non corrispondono.', 'error')
        return redirect(url_for('account'))

    if current_user.check_password(new_password):
        flash('La nuova password deve essere diversa da quella attuale.', 'error')
        return redirect(url_for('account'))

    password_validation = PasswordValidator.validate_strength(new_password, current_user.username)
    if not password_validation['is_strong']:
        flash('La nuova password non soddisfa i requisiti di sicurezza.', 'error')
        return redirect(url_for('account'))

    try:
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        current_user.password = hashed_password
        db.session.commit()

        create_log(
            ip=request.remote_addr,
            log_type="PASSWORD_CHANGE_SUCCESS",
            user=current_user,
            is_error=False
        )
        
        flash('Password cambiata con successo!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Errore durante il cambio password.', 'error')
    
    return redirect(url_for('account'))


@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    if current_user.is_admin:
        flash('Gli account amministratore non possono essere eliminati.', 'error')
        return redirect(url_for('account'))
    
    password = request.form.get('password')

    if not password or not current_user.check_password(password):
        create_log(
            ip=request.remote_addr,
            log_type="ACCOUNT_DELETE_FAILED",
            user=current_user,
            is_error=True
        )
        flash('Password non corretta. Eliminazione annullata.', 'error')
        return redirect(url_for('account'))
    
    try:
        username = current_user.username
        user_id = current_user.id

        create_log(
            ip=request.remote_addr,
            log_type="ACCOUNT_DELETED",
            user=current_user,
            is_error=False
        )

        logout_user()

        from model.user import User
        user_to_delete = User.query.get(user_id)
        if user_to_delete:
            db.session.delete(user_to_delete)
            db.session.commit()
        
        flash(f'Account "{username}" eliminato con successo.', 'success')
        return redirect(url_for('login'))
        
    except Exception as e:
        db.session.rollback()
        flash('Errore durante l\'eliminazione dell\'account.', 'error')
        return redirect(url_for('account'))


@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')


@app.route('/terms-conditions')
def terms_conditions():
    return render_template('terms_conditions.html')


@app.route('/contatti', methods=['GET', 'POST'])
@login_required
def contatti():
    """Pagina contatti con form validato per rilevare input malevoli"""
    if request.method == 'POST':
        nome = request.form.get('nome', '')
        email = request.form.get('email', '')
        messaggio = request.form.get('messaggio', '')
        
        # Validazione completa di tutti i campi
        fields_to_validate = {
            'nome': nome,
            'email': email,
            'messaggio': messaggio
        }
        
        malicious_detected = False
        attack_types = []
        
        # Valida ogni campo per TUTTI i tipi di attacco
        for field_name, field_value in fields_to_validate.items():
            if field_value:  # Solo se il campo non è vuoto
                validation = InputValidator.validate(field_value, field_name)
                
                if not validation['is_safe']:
                    malicious_detected = True
                    attack_type = validation['attack_type']
                    attack_types.append(attack_type)
                    
                    # LOG: Input malevolo rilevato
                    create_log(
                        ip=request.remote_addr,
                        log_type=f"MALICIOUS_INPUT_{attack_type}",
                        user=current_user,
                        is_error=True
                    )
        
        # Se rilevato input malevolo, blocca e avvisa
        if malicious_detected:
            flash('⚠️ Input sospetto rilevato. Messaggio bloccato per motivi di sicurezza.', 'error')
            return render_template('contatti.html')
        
        # Se tutto ok, conferma invio
        # LOG: Messaggio di contatto inviato con successo
        create_log(
            ip=request.remote_addr,
            log_type="CONTACT_FORM_SUCCESS",
            user=current_user,
            is_error=False
        )
        
        flash(f'✅ Grazie {nome}! Il tuo messaggio è stato inviato con successo. Ti risponderemo presto all\'indirizzo {email}.', 'success')
        return redirect(url_for('contatti'))
    
    return render_template('contatti.html')


@app.errorhandler(404)
def page_not_found(e):
    """Gestisce errori 404 - Pagina non trovata"""
    create_log(
        ip=request.remote_addr,
        log_type="PAGE_NOT_FOUND",
        user=current_user if current_user.is_authenticated else None,
        is_error=True
    )
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    """Gestisce errori 500 - Errore interno del server"""
    create_log(
        ip=request.remote_addr,
        log_type="INTERNAL_SERVER_ERROR",
        user=current_user if current_user.is_authenticated else None,
        is_error=True
    )
    return render_template('500.html'), 500


if __name__ == '__main__':

    with app.app_context():
        db.create_all()
        ensure_admin_user()
    app.run(debug=True)