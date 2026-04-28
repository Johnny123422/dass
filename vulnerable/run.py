from app import create_app

app = create_app()

if __name__ == "__main__":
    # VULNERABILITATE: debug=True in productie expune Werkzeug debugger
    app.run(debug=True, host="0.0.0.0", port=5000)
