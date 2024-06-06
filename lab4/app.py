from flask import Flask, render_template, redirect, url_for, request, make_response, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from mysql_db import MySQL

login_manager = LoginManager();

app = Flask(__name__)

app.config.from_pyfile('config.py')

mysql = MySQL(app)

login_manager.init_app(app);
login_manager.login_view = 'login'
login_manager.login_message = 'Доступ к данной странице есть только у авторизованных пользователей '
login_manager.login_message_category = 'warning'


class User(UserMixin):
    def __init__(self,user_id,login):
        self.id = user_id
        self.login = login
        

@login_manager.user_loader
def load_user(user_id):
    cursor = mysql.connection().cursor(named_tuple=True)
    cursor.execute('SELECT * FROM users WHERE id=%s',(user_id,))
    user = cursor.fetchone()
    if user:
        return User(user_id=user.id,login=user.login)
    return None

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/users/')
@login_required
def users():
    cursor = mysql.connection().cursor()
    cursor.execute('''
        SELECT users.id, users.login, users.first_name, users.last_name, users.middle_name, roles.name
        FROM users
        INNER JOIN roles ON users.roles_id = roles.id
    ''')
    users = cursor.fetchall()
    return render_template('users/index.html', users=users)


@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == "POST":
        login = request.form.get('login')
        password = request.form.get('password')
        remember = request.form.get('remember')
        if login and password:
            cursor = mysql.connection().cursor(named_tuple=True)
            cursor.execute('SELECT * FROM users WHERE login=%s AND password_hash = SHA2(%s, 256)',(login,password))
            user = cursor.fetchone()
            if user:
                login_user(User(user_id=user.id,login=user.login),remember=remember)
                flash('Вы успешно прошли аутентификацию', 'success')
                next = request.args.get('next')
                return redirect(next or url_for('index'))
        flash('Неверные логин или пароль', 'danger')
    return render_template('login.html')


# @app.route('/users/register', methods=['GET','POST'])
# @login_required
# def register():
#     if request.method == "GET":
#         return render_template('users/register.html')

#     login = request.form.get('loginInput')
#     password = request.form.get('passwordInput')
#     first_name = request.form.get('firstNameInput')
#     last_name = request.form.get('lastNameInput')
#     middle_name = request.form.get('middleNameInput')
#     roles_id = request.form.get('RoleIdInput')
#     cursor = mysql.connection().cursor(named_tuple=True)
#     query = """INSERT INTO users 
#                (login, password_hash, first_name, last_name, middle_name, roles_id)
#                VALUES (%s, SHA2(%s, 256), %s, %s, %s, %s)"""
#     cursor.execute(query, (login, password, first_name, last_name, middle_name, roles_id))
#     mysql.connection().commit()
#     cursor.close()
#     flash('Успешная регистрация', 'success')
#     return redirect(url_for('users'))

@app.route('/users/register', methods=['GET', 'POST'])
@login_required
def register():
    if request.method == "GET":
        return render_template('users/register.html')
    errorm =''
    errorm1 =''
    errorm2 ='' 
    message = False
    message1 = False
    message2 = False
    login = request.form.get('loginInput')
    password = request.form.get('passwordInput')
    first_name = request.form.get('firstNameInput')
    last_name = request.form.get('lastNameInput')
    middle_name = request.form.get('middleNameInput')
    roles_id = request.form.get('RoleIdInput')
    valid_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    valid_chars1 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789абвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ~!?@#$%^&*_-+()[]}{></\|.,:;"
    stroch = "abcdefghijklmnopqrstuvwxyzабвгдеёжзийклмнопрстуфхцчшщъыьэюя"
    zaglav = "ABCDEFGHIJKLMNOPQRSTUVWXYZАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
    cifra = "0123456789"
    digits = ''
    digits1 = ''
    if login !='':
        if password !='':
            if  first_name !='':
                for char in login:
                    if char in valid_chars:
                            digits += char
                    else:
                        flash('Недопустимый ввод. В логине встречаются недопустимые символы.', 'danger')
                        return render_template('users/register.html')
                for char1 in password:
                    if char1 in valid_chars1:
                            digits1 += char1
                    else:
                        flash('Недопустимый ввод. В пароле встречаются недопустимые символы.', 'danger')
                        return render_template('users/register.html')
                    
                for char2 in password:
                    if char2 in stroch:
                        message = True
                    
                for char3 in password:
                    if char3 in zaglav:
                        message1 = True
                    
                for char4 in password:
                    if char4 in cifra:

                            message2 = True


                    count = len(digits)
                    count1 = len(digits1)

                    if count >= 5:
                        if count1 >= 8 and count1 <= 128: 
                            if message:
                                if message1:
                                    if message2:
                                        cursor = mysql.connection().cursor(named_tuple=True)
                                        query = """INSERT INTO users (login, password_hash, first_name, last_name, middle_name, roles_id) VALUES (%s, SHA2(%s, 256), %s, %s, %s, %s)"""
                                        cursor.execute(query, (login, password, first_name, last_name, middle_name, roles_id))
                                        mysql.connection().commit()
                                        cursor.close()
                                        flash('Успешная регистрация', 'success')
                                        return redirect(url_for('users'))
                                    else:
                                        errorm1 ='Нехватает числа в пароле.'
                                        return render_template('users/register.html', errorm=errorm, errorm1=errorm1, errorm2=errorm2)
                                else:
                                    errorm1 ='Нехватает заглавной в пароле.'
                                    return render_template('users/register.html', errorm=errorm, errorm1=errorm1, errorm2=errorm2)
                            else:
                                errorm1 ='Нехватает строчной в пароле.'
                                return render_template('users/register.html', errorm=errorm, errorm1=errorm1, errorm2=errorm2)
                        else:
                            errorm1 ='Недопустимый ввод. Неверное количество символов в пароле.'
                            return render_template('users/register.html', errorm=errorm, errorm1=errorm1, errorm2=errorm2)
                    else:
                        errorm1 ='Недопустимый ввод. Неверное количество символов в логине.'
                        return render_template('users/register.html', errorm=errorm, errorm1=errorm1, errorm2=errorm2)
            else:
                errorm2 ='Имя обязательно.'
                return render_template('users/register.html', errorm=errorm, errorm1=errorm1, errorm2=errorm2)
        else:
            errorm1 ='Пароль обязателен.'
            return render_template('users/register.html', errorm=errorm, errorm1=errorm1, errorm2=errorm2)
    else:
        errorm ='Логин обязателен.'
        return render_template('users/register.html', errorm=errorm, errorm1=errorm1, errorm2=errorm2)



@app.route('/users/<int:user_id>')
@login_required
def view_user(user_id):
    cursor = mysql.connection().cursor(named_tuple=True)
    cursor.execute('SELECT * FROM users WHERE id = %s ', (user_id,))
    user = cursor.fetchone()
    if user:
        return render_template('/users/view.html', user=user)
    else:
        flash('User not found', 'danger')
        return redirect(url_for('index.html'))

@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if request.method == 'POST':
        login = request.form.get('login')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        try:
            with mysql.connection().cursor(named_tuple=True) as cursor:
                cursor.execute('UPDATE users SET login = %s, first_name = %s, last_name = %s WHERE id = %s', (login, first_name, last_name, user_id,))
                mysql.connection().commit()
                flash('Сведения о пользователи успешно сохранены', 'success')
                return redirect(url_for('view_user', user_id=user_id))
        except Exception as e:
             mysql.connection().rollback()
             flash('Ошбика', 'danger')
             return render_template('users/edit.html')
    else:
        cursor = mysql.connection().cursor(named_tuple=True)
        cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        if user:
            return render_template('users/edit.html', user=user)
        flash('Пользователь не найден', 'danger')
        return redirect(url_for('index.html'))

@app.route('/<int:user_id>/change', methods=['GET', 'POST'])
@login_required
def change_user_pas(user_id):
    if request.method == "GET":
        return render_template('change.html')
      
    password1 = request.form.get('passwordInput1')
    password2 = request.form.get('passwordInput2')
    password3 = request.form.get('passwordInput3')
    cursor1 = mysql.connection().cursor(named_tuple=True)
    cursor1.execute('SELECT * FROM users WHERE id=%s AND password_hash = SHA2(%s, 256)',(user_id,password1))
    user = cursor1.fetchone()
    valid_chars1 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789абвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ~!?@#$%^&*_-+()[]}{></\|.,:;"
    stroch = "abcdefghijklmnopqrstuvwxyzабвгдеёжзийклмнопрстуфхцчшщъыьэюя"
    zaglav = "ABCDEFGHIJKLMNOPQRSTUVWXYZАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
    cifra = "0123456789"
    digits1 = ''
    errorm =''
    errorm1 =''
    errorm2 ='' 
    for char1 in password2:
                    if char1 in valid_chars1:
                            digits1 += char1
                    else:
                        flash('Недопустимый ввод. В пароле встречаются недопустимые символы.', 'danger')
                        return render_template('/change.html')
    for char2 in password2:
        if char2 in stroch:
            message = True
                    
    for char3 in password2:
        if char3 in zaglav:
            message1 = True
        
    for char4 in password2:
        if char4 in cifra:
            message2 = True
    count1 = len(digits1)
    if user:
        if password2 == password3:
            if count1 >= 8 and count1 <= 128: 
                if message:
                    if message1:
                        if message2:
                            cursor = mysql.connection().cursor(named_tuple=True)
                            query = """UPDATE users SET password_hash = SHA2(%s, 256) WHERE id = %s"""
                            cursor.execute(query, ( password2,user_id))
                            mysql.connection().commit()
                            cursor.close()
                            flash('Успешное обновление пароля', 'success')
                            return redirect(url_for('index'))
                        else:
                            errorm1='Нехватает числа в пароле.'
                            return render_template('/change.html', errorm=errorm, errorm1=errorm1, errorm2=errorm2)
                    else:
                        errorm1='Нехватает заглавной в пароле.'
                        return render_template('/change.html', errorm=errorm, errorm1=errorm1, errorm2=errorm2)
                else:
                    errorm1='Нехватает строчной в пароле.'
                    return render_template('/change.html', errorm=errorm, errorm1=errorm1, errorm2=errorm2)
            else:
                errorm1='Недопустимый ввод. Неверное количество символов в пароле.'
                return render_template('/change.html', errorm=errorm, errorm1=errorm1, errorm2=errorm2)
        else:
            errorm2='Пароли не совпадают'
            return render_template('/change.html', errorm=errorm, errorm1=errorm1, errorm2=errorm2)
    else:
        errorm='Старый пароль не верен'
        return render_template('/change.html', errorm=errorm, errorm1=errorm1, errorm2=errorm2)

    
    
@app.route('/users/<int:user_id>/delete', methods=['GET','POST'])
@login_required
def delete_user(user_id):
    cursor = mysql.connection().cursor(named_tuple=True)
    cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
    mysql.connection().commit()
    flash('Пользователь успешно удалён', 'success')
    return redirect(url_for('users'))
   

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


