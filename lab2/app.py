from flask import Flask, render_template, request, make_response

app = Flask(__name__)
application = app


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/args')
def args():
    return render_template('args.html')


@app.route('/headers')
def headers():
    return render_template('headers.html')


@app.route('/cookie')
def cookies():
    resp = make_response(render_template('cookie.html'))
    if "user" in request.cookies:
        resp.delete_cookie("user")
    else:
        resp.set_cookie("user","fughiujhkgfy")
    return resp


@app.route('/form', methods=['GET', 'POST'])
def form():
    return render_template('form.html')


def do_calc(operand1, operand2, action):
    if not operand1 or not operand2 or not action:
        return ''
    res = 0
    match action:
        case '+':
            res = int(operand1) + int(operand2)
        case '-':
            res = int(operand1) - int(operand2)
        case '*':
            res = int(operand1) * int(operand2)
        case '/':
            res = int(operand1) / int(operand2)
    return res


@app.route('/calc')
def calc():
    operand1 = request.args.get('operand1')
    operand2 = request.args.get('operand2')
    action = request.args.get('action')

    result = do_calc(operand1, operand2, action)

    return render_template('calc.html', result=result)

@app.route('/form_phone', methods=['GET', 'POST'])
def form_phone():
    error_message = ''
    original_phone_number = ''
    formatted_phone_number = ''
    if request.method == 'POST':
        original_phone_number = request.form['param1']
        valid_chars = "0123456789 ()-+."
        digits = ''

        for char in original_phone_number:
            if char in valid_chars:
                if char.isdigit():
                    digits += char
            else:
                error_message = 'Недопустимый ввод. В номере телефона встречаются недопустимые символы.'
                break

        if not error_message:
            digit_count = len(digits)

            if digit_count == 11 and original_phone_number.startswith(('8', '+7')):
                formatted_phone_number = f'8-{digits[1:4]}-{digits[4:7]}-{digits[7:9]}-{digits[9:11]}'
            elif digit_count == 10:
                formatted_phone_number = f'8-{digits[0:3]}-{digits[3:6]}-{digits[6:8]}-{digits[8:10]}'
            else:
                error_message = 'Недопустимый ввод. Неверное количество цифр.'

    return render_template('form_phone.html', error_message=error_message, original_phone_number=original_phone_number, formatted_phone_number=formatted_phone_number)


if __name__ == '__main__':
    app.run(debug=True)