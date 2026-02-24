from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'chave_super_secreta'

# Usuário fixo (sem banco de dados)
usuario_fixo = {
    "email": "admin@tech.com",
    "senha": generate_password_hash("123456")
}

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']

        if email == usuario_fixo['email'] and check_password_hash(usuario_fixo['senha'], senha):
            session['usuario'] = email
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', erro="Email ou senha inválidos!")

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', usuario=session['usuario'])

@app.route('/logout')
def logout():
    session.pop('usuario', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)