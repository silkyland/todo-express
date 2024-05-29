# TODO Application Setup Scripts

This repository contains setup scripts for creating a JWT-based TODO application with SQLite. The scripts are available for the following frameworks:

- Express.js (Node.js)
- Flask (Python)
- Go (Golang)

## Requirements

- For Express.js: Node.js, npm
- For Flask: Python3, pip
- For Go: Golang

## Setup Instructions

### Express.js

1. Make the script executable:

   ```sh
   chmod +x easy-express.sh
   ```

2. Run the script:

   ```sh
   ./easy-express.sh
   ```

3. The script will:
   - Install Node.js and npm if not already installed.
   - Initialize a new Node.js project.
   - Install necessary dependencies.
   - Set up the project structure.
   - Start the Express.js server.

### Flask

1. Make the script executable:

   ```sh
   chmod +x easy-flask.sh
   ```

2. Run the script:

   ```sh
   ./easy-flask.sh
   ```

3. The script will:
   - Install Python3 and pip if not already installed.
   - Create a virtual environment.
   - Install necessary dependencies.
   - Set up the project structure.
   - Initialize the SQLite database and apply migrations.
   - Start the Flask development server.

### Go

1. Make the script executable:

   ```sh
   chmod +x easy-golang.sh
   ```

2. Run the script:

   ```sh
   ./easy-golang.sh
   ```

3. The script will:
   - Install Go if not already installed.
   - Create a Go project directory and initialize a Go module.
   - Install necessary dependencies.
   - Set up the project structure.
   - Start the Go server.

## API Endpoints

The following endpoints are available for the TODO application:

### Authentication

- **POST /register**: Register a new user.
- **POST /login**: Login an existing user.

### TODOs

- **GET /todos**: Get all TODOs for the logged-in user.
- **POST /todos**: Create a new TODO.
- **PUT /todos/:id**: Update an existing TODO.
- **DELETE /todos/:id**: Delete a TODO.

## Notes

- Ensure that you have the necessary permissions to install packages and create directories.
- Modify the secret key and other configurations as needed for your application.
- The scripts are intended for development purposes. Adjustments may be required for production use.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
