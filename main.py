from flask import Flask, render_template, request, redirect, url_for, session
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
import os
from time import time

app = Flask(__name__)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

# Güvenlik anahtarı (oturumları güvence altına almak için)
app.secret_key = os.urandom(24)

# Doğru kullanıcı adı ve şifre (şifre bcrypt ile şifrelenmiş durumda)
USERNAME = "ENES"
PASSWORD_HASH = bcrypt.generate_password_hash("fdhkzy123").decode('utf-8')

# Giriş denemeleri ve kilitleme kontrolü
login_attempts = {}
MAX_ATTEMPTS = 5
BLOCK_TIME = 300  # 5 dakika

# Güçlü şifre kontrolü
def is_strong_password(password):
    if len(password) < 8:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char in "!@#$%^&*()_+-=[]{}|;':,.<>?/" for char in password):
        return False
    return True

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Hesap kilitleme kontrolü
        current_time = time()
        if username not in login_attempts:
            login_attempts[username] = {'attempts': 0, 'last_attempt': current_time}
        
        if login_attempts[username]['attempts'] >= MAX_ATTEMPTS:
            if current_time - login_attempts[username]['last_attempt'] < BLOCK_TIME:
                return "Çok fazla deneme yaptınız. Lütfen daha sonra tekrar deneyin."
            else:
                login_attempts[username]['attempts'] = 0  # Zaman aşımından sonra sıfırlama
        
        # Kullanıcı doğrulaması
        if username == USERNAME and bcrypt.check_password_hash(PASSWORD_HASH, password):
            session['username'] = username
            login_attempts[username]['attempts'] = 0  # Giriş başarılıysa denemeleri sıfırla
            return redirect(url_for('welcome'))
        else:
            login_attempts[username]['attempts'] += 1  # Başarısız giriş kaydet
            login_attempts[username]['last_attempt'] = current_time  # Son deneme zamanını güncelle
            return "Yanlış kullanıcı adı veya şifre!"
    return render_template('login.html')

# Giriş sonrası hoş geldiniz ekranı
@app.route('/welcome')
def welcome():
    if 'username' in session:
        username = session['username']
        return f"DARKTURİZM'E HOŞGELDİNİZ BAY {username}"
    else:
        return redirect(url_for('login'))

# Çıkış işlemi
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run()  # HTTP ile çalıştır

