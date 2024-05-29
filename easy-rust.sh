#!/bin/bash

# Function to print messages
print_message() {
    echo "-------------------------------------"
    echo $1
    echo "-------------------------------------"
}

# Print starting message
print_message "Starting setup of Rocket-based TODO Rust application with SQLite and JWT"

# Install Rust if not installed
if ! command -v rustc &> /dev/null
then
    print_message "Rust is not installed. Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
else
    print_message "Rust is already installed"
fi

rustup override set nightly

# Create a new Rust project
print_message "Creating a new Rust project"
cargo new todo-app
cd todo-app

# Add dependencies to Cargo.toml
print_message "Adding dependencies to Cargo.toml"
cat <<EOT >> Cargo.toml

rocket = "0.5.0-rc.1"
rocket_contrib = "0.4.11"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
diesel = { version = "1.4.5", features = ["sqlite"] }
dotenv = "0.15.0"
jsonwebtoken = "8.0"
bcrypt = "0.12"
chrono = "0.4"
EOT

# Create .env file
print_message "Creating .env file"
cat <<EOT > .env
DATABASE_URL=sqlite:todo.db
SECRET_KEY=your_super_secret_key
EOT

# Create Rocket configuration file
print_message "Creating Rocket configuration file"
cat <<EOT > Rocket.toml
[default]
address = "127.0.0.1"
port = 8000
workers = 4
log = "normal"
secret_key = "your_super_secret_key"
databases = ["sqlite"]

[global.databases]
sqlite = { url = "sqlite:todo.db" }
EOT

# Create the main file structure
print_message "Creating the main file structure"
mkdir -p src/models src/controllers src/schema

# Add main.rs
print_message "Adding main.rs"
cat <<EOT > src/main.rs
#[macro_use] extern crate rocket;
#[macro_use] extern crate diesel;

mod models;
mod controllers;
mod schema;

use rocket::fairing::AdHoc;
use rocket::serde::json::Json;
use rocket::tokio::task;

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(AdHoc::on_ignite("Database Migrations", run_db_migrations))
        .mount("/api", routes![
            controllers::auth::register,
            controllers::auth::login,
            controllers::todo::get_todos,
            controllers::todo::create_todo,
            controllers::todo::update_todo,
            controllers::todo::delete_todo
        ])
}

async fn run_db_migrations() {
    task::spawn_blocking(|| {
        let connection = models::establish_connection();
        diesel_migrations::run_pending_migrations(&connection).expect("Failed to run database migrations");
    }).await.expect("Failed to run database migrations in blocking task");
}
EOT

# Add models.rs
print_message "Adding models.rs"
cat <<EOT > src/models/mod.rs
pub mod user;
pub mod todo;

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use std::env;

pub fn establish_connection() -> SqliteConnection {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    SqliteConnection::establish(&database_url).expect(&format!("Error connecting to {}", database_url))
}

pub fn run_migrations(connection: &SqliteConnection) {
    diesel_migrations::run_pending_migrations(connection).expect("Failed to run migrations");
}
EOT

# Add user.rs
print_message "Adding user.rs"
cat <<EOT > src/models/user.rs
use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use super::schema::users;
use bcrypt::{hash, verify, DEFAULT_COST};

#[derive(Queryable, Serialize)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password: String,
}

#[derive(Insertable, Deserialize)]
#[table_name = "users"]
pub struct NewUser {
    pub username: String,
    pub password: String,
}

impl NewUser {
    pub fn hash_password(&mut self) {
        self.password = hash(&self.password, DEFAULT_COST).unwrap();
    }

    pub fn verify_password(&self, password: &str) -> bool {
        verify(password, &self.password).unwrap()
    }
}
EOT

# Add todo.rs
print_message "Adding todo.rs"
cat <<EOT > src/models/todo.rs
use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use super::schema::todos;
use chrono::NaiveDateTime;

#[derive(Queryable, Serialize)]
pub struct Todo {
    pub id: i32,
    pub user_id: i32,
    pub todo: String,
    pub completed: bool,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Insertable, Deserialize)]
#[table_name = "todos"]
pub struct NewTodo {
    pub user_id: i32,
    pub todo: String,
    pub completed: bool,
}
EOT

# Add schema.rs
print_message "Adding schema.rs"
cat <<EOT > src/schema.rs
table! {
    users (id) {
        id -> Integer,
        username -> Text,
        password -> Text,
    }
}

table! {
    todos (id) {
        id -> Integer,
        user_id -> Integer,
        todo -> Text,
        completed -> Bool,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}
EOT

# Add controllers/auth.rs
print_message "Adding controllers/auth.rs"
cat <<EOT > src/controllers/auth.rs
use rocket::serde::json::Json;
use crate::models::user::{User, NewUser};
use diesel::prelude::*;
use crate::schema::users;
use crate::models::establish_connection;
use rocket::http::Status;
use rocket::serde::json::Value;
use jsonwebtoken::{encode, Header, EncodingKey};
use chrono::{Utc, Duration};

#[derive(Deserialize)]
struct AuthData {
    username: String,
    password: String,
}

#[post("/register", data = "<auth_data>")]
pub async fn register(auth_data: Json<AuthData>) -> Result<Json<Value>, Status> {
    let mut new_user = NewUser {
        username: auth_data.username.clone(),
        password: auth_data.password.clone(),
    };
    new_user.hash_password();

    let connection = establish_connection();
    diesel::insert_into(users::table)
        .values(&new_user)
        .execute(&connection)
        .map_err(|_| Status::InternalServerError)?;

    Ok(Json(json!({ "message": "User registered" })))
}

#[post("/login", data = "<auth_data>")]
pub async fn login(auth_data: Json<AuthData>) -> Result<Json<Value>, Status> {
    let connection = establish_connection();
    let user = users::table
        .filter(users::username.eq(&auth_data.username))
        .first::<User>(&connection)
        .map_err(|_| Status::Unauthorized)?;

    if !user.verify_password(&auth_data.password) {
        return Err(Status::Unauthorized);
    }

    let expiration = Utc::now() + Duration::hours(24);
    let claims = Claims {
        sub: user.id,
        exp: expiration.timestamp(),
    };

    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret("your_super_secret_key".as_ref()))
        .map_err(|_| Status::InternalServerError)?;

    Ok(Json(json!({ "token": token })))
}

#[derive(Serialize)]
struct Claims {
    sub: i32,
    exp: i64,
}
EOT

# Add controllers/todo.rs
print_message "Adding controllers/todo.rs"
cat <<EOT > src/controllers/todo.rs
use rocket::serde::json::Json;
use diesel::prelude::*;
use crate::models::todo::{Todo, NewTodo};
use crate::models::establish_connection;
use crate::schema::todos;
use rocket::http::Status;
use rocket::serde::json::Value;

#[derive(Deserialize)]
struct TodoData {
    todo: String,
    completed: bool,
}

#[get("/todos")]
pub async fn get_todos() -> Json<Vec<Todo>> {
    let connection = establish_connection();
    let results = todos::table
        .load::<Todo>(&connection)
        .expect("Error loading todos");
    Json(results)
}

#[post("/todos", data = "<todo_data>")]
pub async fn create_todo(todo_data: Json<TodoData>) -> Result<Json<Todo>, Status> {
    let new_todo = NewTodo {
        user_id: 1, // Replace with real user_id after implementing authentication
        todo: todo_data.todo.clone(),
        completed: todo_data.completed,
    };

    let connection = establish_connection();
    diesel::insert_into(todos::table)
        .values(&new_todo)
        .execute(&connection)
        .map_err(|_| Status::InternalServerError)?;

    let inserted_todo = todos::table.order(todos::id.desc()).first::<Todo>(&connection).unwrap();
    Ok(Json(inserted_todo))
}

#[put("/todos/<id>", data = "<todo_data>")]
pub async fn update_todo(id: i32, todo_data: Json<TodoData>) -> Result<Json<Todo>, Status> {
    let connection = establish_connection();
    diesel::update(todos::table.find(id))
        .set((todos::todo.eq(&todo_data.todo), todos::completed.eq(todo_data.completed)))
        .execute(&connection)
        .map_err(|_| Status::InternalServerError)?;

    let updated_todo = todos::table.find(id).first::<Todo>(&connection).unwrap();
    Ok(Json(updated_todo))
}

#[delete("/todos/<id>")]
pub async fn delete_todo(id: i32) -> Result<Json<Value>, Status> {
    let connection = establish_connection();
    diesel::delete(todos::table.find(id))
        .execute(&connection)
        .map_err(|_| Status::InternalServerError)?;

    Ok(Json(json!({ "message": "Todo deleted" })))
}
EOT

# Run the server
print_message "Starting the server"
cargo run
