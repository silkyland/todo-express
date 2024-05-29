#!/bin/bash

# Function to print messages
print_message() {
    echo "-------------------------------------"
    echo $1
    echo "-------------------------------------"
}

# Print starting message
print_message "Starting setup of JWT-based TODO Express application with TypeScript and SQLite"

# Update package list and install Node.js if not installed
if ! command -v node &> /dev/null
then
    print_message "Node.js is not installed. Installing Node.js and npm..."
    curl -fsSL https://deb.nodesource.com/setup_16.x | bash -
    apt-get install -y nodejs
else
    print_message "Node.js is already installed"
fi

# Install npm if not installed
if ! command -v npm &> /dev/null
then
    print_message "npm is not installed. Installing npm..."
    apt-get install -y npm
else
    print_message "npm is already installed"
fi

# Install TypeScript globally if not installed
if ! command -v tsc &> /dev/null
then
    print_message "TypeScript is not installed. Installing TypeScript..."
    npm install -g typescript
else
    print_message "TypeScript is already installed"
fi

# create todos-express folder and enter it
mkdir todos-express
cd todos-express

# Initialize the project
print_message "Initializing the project"
npm init -y

# Install dependencies
print_message "Installing dependencies"
npm install express typescript ts-node @types/express jsonwebtoken @types/jsonwebtoken body-parser @types/body-parser better-sqlite3 @types/better-sqlite3 bcryptjs @types/bcryptjs

# Initialize TypeScript
print_message "Initializing TypeScript"
npx tsc --init

# Create necessary folders and files
print_message "Creating necessary folders and files"
mkdir -p src
cd src
touch index.ts auth.ts todo.ts database.ts types.ts

# Add sample TypeScript configuration
print_message "Adding TypeScript configuration"
cat <<EOT > ../tsconfig.json
{
  "compilerOptions": {
    "target": "ES6",
    "module": "commonjs",
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true
  }
}
EOT

# Add type definitions in types.ts
print_message "Adding type definitions"
cat <<EOT > types.ts
export interface User {
  id: number;
  username: string;
  password: string;
}

export interface Todo {
  id: number;
  userId: number;
  todo: string;
  completed: number;
  created_at: string;
  updated_at: string;
}
EOT

# Add database setup code in database.ts
print_message "Adding database setup code"
cat <<EOT > database.ts
import Database from 'better-sqlite3';
import { User, Todo } from './types';

export const initDb = () => {
  const db = new Database('database.sqlite');

  db.exec(\`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT, 
      username TEXT UNIQUE, 
      password TEXT
    )
  \`);
  db.exec(\`
    CREATE TABLE IF NOT EXISTS todos (
      id INTEGER PRIMARY KEY AUTOINCREMENT, 
      userId INTEGER, 
      todo TEXT, 
      completed INTEGER DEFAULT 0, 
      created_at TEXT DEFAULT CURRENT_TIMESTAMP, 
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP, 
      FOREIGN KEY(userId) REFERENCES users(id)
    )
  \`);

  return db;
};
EOT

# Add sample Express server code in index.ts
print_message "Adding sample Express server code"
cat <<EOT > index.ts
import express from "express";
import bodyParser from "body-parser";
import { authRouter } from "./auth";
import { todoRouter } from "./todo";
import { initDb } from "./database";

const app = express();
const port = 3000;

app.use(bodyParser.json());

const db = initDb();
app.locals.db = db;
app.use("/auth", authRouter);
app.use("/todo", todoRouter);

app.listen(port, () => {
  console.log(\`Server running at http://localhost:\${port}\`);
});
EOT

# Add sample authentication code in auth.ts
print_message "Adding sample authentication code"
cat <<EOT > auth.ts
import { Router } from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { User } from "./types";

const authRouter = Router();
const SECRET_KEY = "secretKey";

authRouter.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const db = req.app.locals.db;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.prepare("INSERT INTO users (username, password) VALUES (?, ?)").run(username, hashedPassword);
    res.status(201).send("User registered");
  } catch (error) {
    res.status(400).send("User already exists");
  }
});

authRouter.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const db = req.app.locals.db;

  const user: User = db.prepare("SELECT * FROM users WHERE username = ?").get(username);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).send("Invalid credentials");
  }

  const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: "1h" });
  res.json({ token });
});

export { authRouter };
EOT

# Add sample ToDo code in todo.ts
print_message "Adding sample ToDo code"
cat <<EOT > todo.ts
import { Router, Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { Todo, User } from "./types";

const todoRouter = Router();
const SECRET_KEY = "secretKey"; // Use the same constant for the secret key

interface AuthRequest extends Request {
  user?: any;
}

const authenticate = (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    return res.status(401).send("Access denied. No token provided.");
  }

  const token = authHeader.split(" ")[1]; // Extract the token from the "Bearer <token>" format
  if (!token) {
    return res.status(401).send("Access denied. Token not found.");
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY); // Use the same secret key for verification
    req.user = decoded;
    next();
  } catch (err) {
    res.status(400).send("Invalid token");
  }
};

todoRouter.use(authenticate);

todoRouter.get("/", (req: AuthRequest, res: Response) => {
  const db = req.app.locals.db;
  const todos: Todo[] = db.prepare("SELECT * FROM todos WHERE userId = ?").all(req.user.id);
  res.json(todos);
});

todoRouter.post("/", (req: AuthRequest, res: Response) => {
  const { todo, completed = false } = req.body;
  const db = req.app.locals.db;

  // Verify if the user exists
  const user: User = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
  if (!user) {
    return res.status(400).send("User not found");
  }

  const createdAt = new Date().toISOString();
  const updatedAt = createdAt;
  const completedInt = completed ? 1 : 0;

  db.prepare("INSERT INTO todos (userId, todo, completed, created_at, updated_at) VALUES (?, ?, ?, ?, ?)")
   .run(req.user.id, todo, completedInt, createdAt, updatedAt);
  res.status(201).send("ToDo item added");
});

todoRouter.put("/:id", (req: AuthRequest, res: Response) => {
  const { id } = req.params;
  const { todo, completed } = req.body;
  const db = req.app.locals.db;

  const updatedAt = new Date().toISOString();

  db.prepare("UPDATE todos SET todo = ?, completed = ?, updated_at = ? WHERE id = ? AND userId = ?")
    .run(todo, completed, updatedAt, id, req.user.id);
  res.send("ToDo item updated");
});

todoRouter.delete("/:id", (req: AuthRequest, res: Response) => {
  const { id } = req.params;
  const db = req.app.locals.db;

  db.prepare("DELETE FROM todos WHERE id = ? AND userId = ?").run(id, req.user.id);
  res.send("ToDo item deleted");
});

export { todoRouter };
EOT

# Compile TypeScript code
print_message "Compiling TypeScript code"
npx tsc

# Run the server
print_message "Starting the server"
node ../dist/index.js
