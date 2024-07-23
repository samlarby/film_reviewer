import os
from flask import (
    Flask, flash, render_template,
    redirect, request, session, url_for)
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
if os.path.exists("env.py"):
    import env

app = Flask(__name__)


app.config["MONGO_DBNAME"] = os.environ.get("MONGO_DBNAME")
app.config["MONGO_URI"] = os.environ.get("MONGO_URI")
app.secret_key = os.environ.get("SECRET_KEY")

mongo = PyMongo(app)





@app.route("/")
@app.route("/films")
def films():
    films = list(mongo.db.films.find())
    return render_template("films.html", films=films)


@app.route("/home")
def home():
    return render_template("home.html")


@app.route("/search", methods=["GET", "POST"])
def search():
    query = request.form.get("query")
    films = list(mongo.db.films.find({"$text": {"$search": query}}))
    return render_template("films.html", films=films)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # check if the username already exists in the database
        existing_user = mongo.db.users.find_one(
            {"username": request.form.get("username").lower()})

        if existing_user:
            flash("Username already exists")
            return redirect(url_for("register"))

        register = {
            "username": request.form.get("username").lower(),
            "password": generate_password_hash(request.form.get("password"))
        }
        mongo.db.users.insert_one(register)

        # put the user in a session cookie
        session["user"] = request.form.get("username").lower()
        flash("Your registration was successful")
        return redirect(url_for("profile", username=session["user"]))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # check if username already exists
        existing_user = mongo.db.users.find_one(
            {"username": request.form.get("username").lower()})
        
        if existing_user:
            # ensure the password matches
            if check_password_hash(
                existing_user["password"], request.form.get("password")):
                    session["user"] = request.form.get("username").lower()
                    flash("Welcome, {}".format(request.form.get("username")))
                    return redirect(
                        url_for("profile", username=session["user"]))
            else:
                # if the password does not match then display a message
                flash("Incorrect password or username was entered")
                return redirect(url_for("login"))

        else:
            # if the username does not exist display message
            flash("Incorrect password or username was entered")
            return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/profile/<username>", methods=["GET", "POST"])
def profile(username):
    # get users username from the database
    username = mongo.db.users.find_one(
        {"username": session["user"]})["username"]
    if session["user"]:
        return render_template("profile.html", username=username)
    return redirect(url_for("login"))


@app.route("/logout")
def logout():
    flash("You have been logged out")
    session.pop("user")
    return redirect(url_for("login"))


@app.route("/add_film", methods=["GET", "POST"])
def add_film():
    if request.method == "POST":
        film = {
            "film_name": request.form.get("film_name"),
            "director": request.form.get("director"),
            "release_year": request.form.get("release_year"),
            "film_image": request.form.get("film_image")
        }
        mongo.db.films.insert_one(film)
        flash("Film successfully added")
        return redirect(url_for('films'))
    return render_template("add_film.html")


@app.route("/edit_film/<film_id>", methods=["GET", "POST"])
def edit_film(film_id):
    if request.method == "POST":
        submit = { "$set": {
            "film_name": request.form.get("film_name"),
            "director": request.form.get("director"),
            "release_year": request.form.get("release_year"),
            "film_image": request.form.get("film_image")
        }}
        mongo.db.films.update_one({"_id": ObjectId(film_id)}, submit)
        flash("Film successfully edited")
    film = mongo.db.films.find_one({"_id":ObjectId(film_id)})
    return render_template("edit_film.html", film=film)


@app.route("/delete_film/<film_id>")
def delete_film(film_id):
    mongo.db.films.delete_one({"_id": ObjectId(film_id)})
    flash("Film successfully deleted")
    return redirect(url_for("films"))


@app.route("/add_review/<film_id>", methods=["GET", "POST"])
def add_review(film_id):
    if request.method == "POST":
        review = {
            "username": request.form.get("username"),
            "text": request.form.get("review"),
            "review_id": str(uuid.uuid4())
        }
        mongo.db.films.update_one(
            {"_id": ObjectId(film_id)},
            {"$push": {"reviews": review}}
        )
        flash("Review successfully added")
        return redirect(url_for('films', film_id=film_id))
    film = mongo.db.films.find_one({"_id": ObjectId(film_id)})
    return render_template("add_review.html", film=film)
    

@app.route("/delete_review/<film_id>/<review_id>")
def delete_review(film_id, review_id):
    mongo.db.films.update_one(
        {"_id": ObjectId(film_id)},
        {"$pull": {"reviews": {"review_id": review_id}}}
    )
    flash("Review successfully deleted")
    return redirect(url_for("films"))

if __name__ == "__main__":
    app.run(host=os.environ.get("IP"),
    port=int(os.environ.get("PORT")),
    debug=True)
