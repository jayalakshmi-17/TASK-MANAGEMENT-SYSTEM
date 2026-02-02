# TASK-MANAGEMENT-SYSTEM
🗄️ DATABASE SCHEMAS
👤 User Model

name

email (unique)

password (hashed)

role (USER / ADMIN)

📝 Task Model

title

description

status (pending / completed)

createdBy (User ID)

🔐 AUTH FLOW (JWT)

User registers → password hashed

User logs in → JWT generated

JWT sent in headers:

Authorization: Bearer <token>


Middleware:

authMiddleware → verifies token

roleMiddleware → checks admin/user

🌐 API DESIGN (Versioned)
🔑 Auth APIs
POST   /api/v1/auth/register
POST   /api/v1/auth/login

📝 Task APIs
POST   /api/v1/tasks        (USER)
GET    /api/v1/tasks        (USER → own tasks, ADMIN → all)
PUT    /api/v1/tasks/:id    (USER → own, ADMIN → any)
DELETE /api/v1/tasks/:id    (ADMIN only)


✔ REST principles
✔ Proper status codes
✔ Clean separation

🖥️ FRONTEND (React.js)
Pages

Register

Login

User Dashboard

Admin Dashboard

Features

JWT stored securely

Protected routes

Task CRUD

Admin controls visible only to admins

API error/success messages shown

📘 Swagger

/api-docs

Auth + Tasks documented

Easy evaluator testing🧱 STEP 1: Initialize Backend Project
📂 Create folder
mkdir backend
cd backend
npm init -y

📦 Install dependencies
npm install express mongoose bcryptjs jsonwebtoken dotenv cors
npm install nodemon --save-dev

🧾 STEP 2: package.json setup

Update scripts section:

"scripts": {
  "start": "node src/server.js",
  "dev": "nodemon src/server.js"
}

🌍 STEP 3: Environment Variables (.env)

Create a .env file in backend/

PORT=5000
MONGO_URI=mongodb://127.0.0.1:27017/task_manager
JWT_SECRET=supersecretjwtkey


👉 (Later you can say: “Secrets are managed using environment variables for security”)

📁 STEP 4: Folder Structure

Create this structure exactly:

backend/
│── src/
│   ├── config/
│   │   └── db.js
│   ├── controllers/
│   │   ├── auth.controller.js
│   │   └── task.controller.js
│   ├── middlewares/
│   │   ├── auth.middleware.js
│   │   └── role.middleware.js
│   ├── models/
│   │   ├── user.model.js
│   │   └── task.model.js
│   ├── routes/
│   │   ├── auth.routes.js
│   │   └── task.routes.js
│   ├── app.js
│   └── server.js


This alone screams “industry ready”.

🔌 STEP 5: MongoDB Connection
src/config/db.js
const mongoose = require("mongoose");

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("MongoDB connected");
  } catch (error) {
    console.error("DB connection failed", error);
    process.exit(1);
  }
};

module.exports = connectDB;

👤 STEP 6: User Model (Auth + Roles)
src/models/user.model.js
const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true
    },
    password: {
      type: String,
      required: true
    },
    role: {
      type: String,
      enum: ["USER", "ADMIN"],
      default: "USER"
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);


✔ Role-based access ready
✔ Secure by default

📝 STEP 7: Task Model (CRUD Entity)
src/models/task.model.js
const mongoose = require("mongoose");

const taskSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true
    },
    description: {
      type: String
    },
    status: {
      type: String,
      enum: ["pending", "completed"],
      default: "pending"
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("Task", taskSchema);

🚀 STEP 8: App & Server Setup
src/app.js
const express = require("express");
const cors = require("cors");

const authRoutes = require("./routes/auth.routes");
const taskRoutes = require("./routes/task.routes");

const app = express();

app.use(cors());
app.use(express.json());

app.use("/api/v1/auth", authRoutes);
app.use("/api/v1/tasks", taskRoutes);

app.get("/", (req, res) => {
  res.send("API is running...");
});

module.exports = app;

src/server.js
require("dotenv").config();
const app = require("./app");
const connectDB = require("./config/db");

const PORT = process.env.PORT || 5000;

connectDB();

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

✅ TEST RUN
npm run dev


If you see:

MongoDB connected
Server running on port 5000


🎉 Backend base is DONE
🔐 STEP 9: Authentication APIs (Register & Login)

We’ll implement:

Password hashing (bcrypt)

JWT token generation

Proper validation & error handling

📦 1️⃣ Auth Controller
src/controllers/auth.controller.js
const User = require("../models/user.model");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

/**
 * @desc Register new user
 * @route POST /api/v1/auth/register
 * @access Public
 */
exports.register = async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "User already exists" });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      role: role || "USER"
    });

    res.status(201).json({
      message: "User registered successfully",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

/**
 * @desc Login user
 * @route POST /api/v1/auth/login
 * @access Public
 */
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    // Check user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Generate JWT
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.status(200).json({
      message: "Login successful",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
};


✔ bcrypt hashing
✔ JWT best practices
✔ Clean responses
✔ Proper status codes

🛣️ 2️⃣ Auth Routes
src/routes/auth.routes.js
const express = require("express");
const router = express.Router();
const { register, login } = require("../controllers/auth.controller");

router.post("/register", register);
router.post("/login", login);

module.exports = router;

🧪 3️⃣ Test Auth APIs (Postman)
✅ Register
POST http://localhost:5000/api/v1/auth/register


Body (JSON):

{
  "name": "Admin User",
  "email": "admin@test.com",
  "password": "admin123",
  "role": "ADMIN"
}

✅ Login
POST http://localhost:5000/api/v1/auth/login


Body:

{
  "email": "admin@test.com",
  "password": "admin123"
}


Response:

{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "name": "Admin User",
    "role": "ADMIN"
  }
}


👉 Save this token — we’ll use it for protected routes.
🛡️ STEP 10: Authentication Middleware (JWT)

This middleware:

Checks token

Verifies JWT

Attaches user info to req.user

🔐 src/middlewares/auth.middleware.js
const jwt = require("jsonwebtoken");

const authMiddleware = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Authorization token missing" });
    }

    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = decoded; // { id, role }
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

module.exports = authMiddleware;


✔ Secure
✔ Stateless
✔ Clean error handling

👮 STEP 11: Role-Based Middleware

This middleware ensures only specific roles can access certain APIs.

🔑 src/middlewares/role.middleware.js
const roleMiddleware = (roles = []) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        message: "Access denied: insufficient permissions"
      });
    }
    next();
  };
};

module.exports = roleMiddleware;


Usage example:

roleMiddleware(["ADMIN"])

🧪 STEP 12: Quick Middleware Test

Add a temporary protected route in app.js (just to test):

const authMiddleware = require("./middlewares/auth.middleware");

app.get("/api/v1/protected", authMiddleware, (req, res) => {
  res.json({
    message: "Access granted",
    user: req.user
  });
});

Test in Postman:
GET http://localhost:5000/api/v1/protected
Authorization: Bearer <JWT_TOKEN>


✅ Works → middleware is correct
❌ No token → 401
❌ Wrong role → 403 (later)
📝 STEP 13: Task CRUD APIs (with Role Logic)
🎯 Rules (Very Important)

USER

Can create tasks

Can view only their own tasks

Can update only their own tasks

ADMIN

Can view all tasks

Can delete any task

This shows proper authorization, not just authentication.

📦 1️⃣ Task Controller
src/controllers/task.controller.js
const Task = require("../models/task.model");

/**
 * @desc Create new task
 * @route POST /api/v1/tasks
 * @access USER
 */
exports.createTask = async (req, res) => {
  try {
    const { title, description } = req.body;

    if (!title) {
      return res.status(400).json({ message: "Title is required" });
    }

    const task = await Task.create({
      title,
      description,
      createdBy: req.user.id
    });

    res.status(201).json({
      message: "Task created successfully",
      task
    });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

/**
 * @desc Get tasks
 * @route GET /api/v1/tasks
 * @access USER / ADMIN
 */
exports.getTasks = async (req, res) => {
  try {
    let tasks;

    if (req.user.role === "ADMIN") {
      tasks = await Task.find().populate("createdBy", "name email");
    } else {
      tasks = await Task.find({ createdBy: req.user.id });
    }

    res.status(200).json({ count: tasks.length, tasks });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

/**
 * @desc Update task
 * @route PUT /api/v1/tasks/:id
 * @access USER / ADMIN
 */
exports.updateTask = async (req, res) => {
  try {
    const task = await Task.findById(req.params.id);

    if (!task) {
      return res.status(404).json({ message: "Task not found" });
    }

    // USER can update only own task
    if (req.user.role === "USER" && task.createdBy.toString() !== req.user.id) {
      return res.status(403).json({ message: "Access denied" });
    }

    task.title = req.body.title || task.title;
    task.description = req.body.description || task.description;
    task.status = req.body.status || task.status;

    await task.save();

    res.status(200).json({
      message: "Task updated successfully",
      task
    });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

/**
 * @desc Delete task
 * @route DELETE /api/v1/tasks/:id
 * @access ADMIN
 */
exports.deleteTask = async (req, res) => {
  try {
    const task = await Task.findById(req.params.id);

    if (!task) {
      return res.status(404).json({ message: "Task not found" });
    }

    await task.deleteOne();

    res.status(200).json({ message: "Task deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
};


✔ Ownership checks
✔ Admin override
✔ Clean logic separation

🛣️ 2️⃣ Task Routes
src/routes/task.routes.js
const express = require("express");
const router = express.Router();

const authMiddleware = require("../middlewares/auth.middleware");
const roleMiddleware = require("../middlewares/role.middleware");

const {
  createTask,
  getTasks,
  updateTask,
  deleteTask
} = require("../controllers/task.controller");

router.post("/", authMiddleware, createTask);
router.get("/", authMiddleware, getTasks);
router.put("/:id", authMiddleware, updateTask);
router.delete("/:id", authMiddleware, roleMiddleware(["ADMIN"]), deleteTask);

module.exports = router;

🧪 STEP 14: Test CRUD APIs (Postman)
✅ Create Task (USER)
POST /api/v1/tasks
Authorization: Bearer <USER_TOKEN>

{
  "title": "Finish backend",
  "description": "Complete auth and CRUD APIs"
}

✅ Get Tasks

USER → sees only own

ADMIN → sees all

GET /api/v1/tasks
Authorization: Bearer <TOKEN>

✅ Update Task
PUT /api/v1/tasks/:id
Authorization: Bearer <TOKEN>

❌ Delete Task (USER)
403 Forbidden

✅ Delete Task (ADMIN)
DELETE /api/v1/tasks/:id
Authorization: Bearer <ADMIN_TOKEN>
📘 STEP 15: Swagger API Documentation

We’ll use:

swagger-ui-express

swagger-jsdoc

📦 1️⃣ Install Swagger Dependencies

Run inside backend/:

npm install swagger-ui-express swagger-jsdoc

📁 2️⃣ Swagger Configuration File
Create: src/config/swagger.js
const swaggerJSDoc = require("swagger-jsdoc");

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Task Management API",
      version: "1.0.0",
      description:
        "Scalable REST API with Authentication and Role-Based Access Control"
    },
    servers: [
      {
        url: "http://localhost:5000"
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT"
        }
      }
    },
    security: [
      {
        bearerAuth: []
      }
    ]
  },
  apis: ["./src/routes/*.js"]
};

module.exports = swaggerJSDoc(options);

🔗 3️⃣ Enable Swagger in app.js
Update src/app.js
const swaggerUi = require("swagger-ui-express");
const swaggerSpec = require("./config/swagger");


Add below routes:

app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));


✅ Now Swagger UI is live at:

http://localhost:5000/api-docs

📝 4️⃣ Add Swagger Comments (Very Important)
Update src/routes/auth.routes.js
/**
 * @swagger
 * tags:
 *   name: Auth
 *   description: Authentication APIs
 */

/**
 * @swagger
 * /api/v1/auth/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - email
 *               - password
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               role:
 *                 type: string
 *     responses:
 *       201:
 *         description: User registered successfully
 */

Update src/routes/task.routes.js
/**
 * @swagger
 * tags:
 *   name: Tasks
 *   description: Task management APIs
 */

/**
 * @swagger
 * /api/v1/tasks:
 *   get:
 *     summary: Get tasks (Admin gets all, User gets own)
 *     tags: [Tasks]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of tasks
 */

/**
 * @swagger
 * /api/v1/tasks:
 *   post:
 *     summary: Create a new task
 *     tags: [Tasks]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - title
 *             properties:
 *               title:
 *                 type: string
 *               description:
 *                 type: string
 *     responses:
 *       201:
 *         description: Task created
 */

/**
 * @swagger
 * /api/v1/tasks/{id}:
 *   delete:
 *     summary: Delete task (Admin only)
 *     tags: [Tasks]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Task deleted
 */

🧪 5️⃣ Test Swagger

Restart server:

npm run dev


Open browser:

http://localhost:5000/api-docs


Click Authorize

Paste:

Bearer <JWT_TOKEN>


🎉 You can now test all protected APIs from UI
🖥️ FRONTEND – REACT.JS (JWT + RBAC)
🎯 What the frontend will do

Register & Login

Store JWT securely

Protected routes

USER dashboard → manage own tasks

ADMIN dashboard → view & delete all tasks

Show API success / error messages

📁 STEP 1: Create React App

In a separate folder (outside backend):

npx create-react-app frontend
cd frontend
npm install axios react-router-dom
npm start

📁 STEP 2: Frontend Folder Structure

Inside src/:

src/
│── api/
│   └── axios.js
│── components/
│   ├── Navbar.js
│   └── ProtectedRoute.js
│── pages/
│   ├── Login.js
│   ├── Register.js
│   ├── UserDashboard.js
│   └── AdminDashboard.js
│── utils/
│   └── auth.js
│── App.js
│── index.js


Clean & scalable ✅

🌐 STEP 3: Axios Setup (JWT handling)
src/api/axios.js
import axios from "axios";

const api = axios.create({
  baseURL: "http://localhost:5000/api/v1"
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export default api;


👉 Automatically attaches JWT to every request.

🔐 STEP 4: Auth Utilities
src/utils/auth.js
export const isAuthenticated = () => {
  return localStorage.getItem("token");
};

export const getUserRole = () => {
  const user = JSON.parse(localStorage.getItem("user"));
  return user?.role;
};

export const logout = () => {
  localStorage.clear();
  window.location.href = "/login";
};

🛡️ STEP 5: Protected Route
src/components/ProtectedRoute.js
import { Navigate } from "react-router-dom";
import { isAuthenticated } from "../utils/auth";

const ProtectedRoute = ({ children }) => {
  return isAuthenticated() ? children : <Navigate to="/login" />;
};

export default ProtectedRoute;

🧭 STEP 6: Routing
src/App.js
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Login from "./pages/Login";
import Register from "./pages/Register";
import UserDashboard from "./pages/UserDashboard";
import AdminDashboard from "./pages/AdminDashboard";
import ProtectedRoute from "./components/ProtectedRoute";

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Login />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />

        <Route
          path="/user"
          element={
            <ProtectedRoute>
              <UserDashboard />
            </ProtectedRoute>
          }
        />

        <Route
          path="/admin"
          element={
            <ProtectedRoute>
              <AdminDashboard />
            </ProtectedRoute>
          }
        />
      </Routes>
    </BrowserRouter>
  );
}

export default App;

🔑 STEP 7: Login Page
src/pages/Login.js
import { useState } from "react";
import api from "../api/axios";

const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const res = await api.post("/auth/login", { email, password });

      localStorage.setItem("token", res.data.token);
      localStorage.setItem("user", JSON.stringify(res.data.user));

      if (res.data.user.role === "ADMIN") {
        window.location.href = "/admin";
      } else {
        window.location.href = "/user";
      }
    } catch (err) {
      setError(err.response?.data?.message || "Login failed");
    }
  };

  return (
    <form onSubmit={handleLogin}>
      <h2>Login</h2>
      {error && <p>{error}</p>}
      <input placeholder="Email" onChange={(e) => setEmail(e.target.value)} />
      <input type="password" placeholder="Password" onChange={(e) => setPassword(e.target.value)} />
      <button type="submit">Login</button>
    </form>
  );
};

export default Login;

📝 STEP 8: Register Page
src/pages/Register.js
import { useState } from "react";
import api from "../api/axios";

const Register = () => {
  const [form, setForm] = useState({});

  const handleRegister = async (e) => {
    e.preventDefault();
    await api.post("/auth/register", form);
    alert("Registered successfully");
    window.location.href = "/login";
  };

  return (
    <form onSubmit={handleRegister}>
      <h2>Register</h2>
      <input placeholder="Name" onChange={(e) => setForm({ ...form, name: e.target.value })} />
      <input placeholder="Email" onChange={(e) => setForm({ ...form, email: e.target.value })} />
      <input type="password" placeholder="Password" onChange={(e) => setForm({ ...form, password: e.target.value })} />
      <button>Register</button>
    </form>
  );
};

export default Register;

🧑‍💻 STEP 9: User Dashboard (CRUD)
src/pages/UserDashboard.js
import { useEffect, useState } from "react";
import api from "../api/axios";
import { logout } from "../utils/auth";

const UserDashboard = () => {
  const [tasks, setTasks] = useState([]);
  const [title, setTitle] = useState("");

  const fetchTasks = async () => {
    const res = await api.get("/tasks");
    setTasks(res.data.tasks);
  };

  const addTask = async () => {
    await api.post("/tasks", { title });
    setTitle("");
    fetchTasks();
  };

  useEffect(() => {
    fetchTasks();
  }, []);

  return (
    <>
      <h2>User Dashboard</h2>
      <button onClick={logout}>Logout</button>

      <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="New task" />
      <button onClick={addTask}>Add</button>

      <ul>
        {tasks.map((t) => (
          <li key={t._id}>{t.title}</li>
        ))}
      </ul>
    </>
  );
};

export default UserDashboard;

👮 STEP 10: Admin Dashboard
src/pages/AdminDashboard.js
import { useEffect, useState } from "react";
import api from "../api/axios";
import { logout } from "../utils/auth";

const AdminDashboard = () => {
  const [tasks, setTasks] = useState([]);

  const fetchTasks = async () => {
    const res = await api.get("/tasks");
    setTasks(res.data.tasks);
  };

  const deleteTask = async (id) => {
    await api.delete(`/tasks/${id}`);
    fetchTasks();
  };

  useEffect(() => {
    fetchTasks();
  }, []);

  return (
    <>
      <h2>Admin Dashboard</h2>
      <button onClick={logout}>Logout</button>

      <ul>
        {tasks.map((t) => (
          <li key={t._id}>
            {t.title} — {t.createdBy?.email}
            <button onClick={() => deleteTask(t._id)}>Delete</button>
          </li>
        ))}
      </ul>
    </>
  );
};

export default AdminDashboard;

✅ FRONTEND DONE 🎉

You now have:

Auth flow

JWT protection

Role-based UI

CRUD integration

Error handling
