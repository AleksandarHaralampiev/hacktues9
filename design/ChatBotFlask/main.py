from flask import Flask, render_template, request
from chat import get_answer

app = Flask(__name__)

@app.get("/")
def index_get():
    return render_template("templates/home.html")

@app.post("/predict")
def predict():
    text = request.form.get("message")
    response = get_answer(text)
    return response

if __name__ == "__main__":
    app.run(debug=True)