#importar librerías
from datetime import datetime, timedelta
from functools import wraps

import jwt
from flask import Flask, jsonify, make_response, request, render_template, session

#generacion de app Flask
app = Flask(__name__)


app.config['SECRET_KEY'] = 'f393e8c9708441398a9d543955b2217c'
# cómo obtener una clave secreta
# En tu linea de comando o terminal >>> accede a Python >>> luego escribe:

# Enfoque del sistema operativo
# import os
# os.urandom(14)

# UUID Approach
# import uuid
# uuid.uuid4().hex

# Secrets [solo para Python 3.6 +]
#import secrets
# secrets.token_urlsafe(14)


def token_required(func):
    # generacion de tokens, invocando el método update_wrapper () y usando la función decorated como argumento
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'Alert!': 'Falta el token!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        # Puede utilizar los errores de JWT como excepción
        # except jwt.InvalidTokenError:
        # return 'Token no válido. Por favor, inicie sesión de nuevo. '
        except:
            return jsonify({'Message': 'Token no Válido'}), 403
        return func(*args, **kwargs)
    return decorated


#ruta principal del servidor web
@app.route('/')
def home():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        return render_template('logout.html')


# Página de login
@app.route('/login', methods=['POST'])
def login():
    if request.form['username'] and request.form['password'] == '12345678':
        session['logged_in'] = True

        token = jwt.encode({
            'Usuario': request.form['username'],
            #hacer uso de la función str, para transformar la fecha actual a un String
            'Token expiracion': str(datetime.utcnow() + timedelta(seconds=60))
        },
            app.config['SECRET_KEY'])
        return jsonify({'token': jwt.decode(token,'f393e8c9708441398a9d543955b2217c',algorithms=['HS256']),
                        'mensaje': 'JWT está verificado. Bienvenid@!'})
    else:
        return make_response('No se puede verificar', 403, {'WWW-Autenticacion-JWT': "Autenticación fallida"})


#metodo para cerrar sesión
@app.route('/logout', methods=['GET'])
def logout():
    return render_template('login.html')



if __name__ == "__main__":
    app.run(debug=True)
