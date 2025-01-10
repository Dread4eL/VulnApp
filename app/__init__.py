from flask import Flask

app = Flask(__name__, template_folder='./templates')
app.config.from_object('config.Config')  # Load configuration

from app import routes  # Import your routes

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
