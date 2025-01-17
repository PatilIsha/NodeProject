const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

// Initialize Express App
const app = express();
app.use(express.json());
app.use(cors());

// MongoDB Connection
const mongoURI = "mongodb+srv://ishapatilgenai:mxspMbPLIDVJWem0@test-db.ybesv.mongodb.net/?retryWrites=true&w=majority&appName=test-db";
mongoose.connect(mongoURI, {})
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.error(err));

// User Schema
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  age: { type: Number, required: true },
  mobile: { type: String, required: true },
  gender: { type: String, required: true },
});

const User = mongoose.model("User", userSchema);

// Middleware to protect routes
const authenticateToken = (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Access denied, token missing!" });

  jwt.verify(token, "secretkey", (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
};

// Routes
app.post("/api/signup", async (req, res) => {
  const { firstName, lastName, email, password, age, mobile, gender } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ firstName, lastName, email, password: hashedPassword, age, mobile, gender });
    await newUser.save();
    res.status(201).json({ message: "User registered successfully!" });
  } catch (error) {
    if (error.code === 11000) {
      res.status(400).json({ error: "Email already exists!" });
    } else {
      console.log(error);
      res.status(500).json({     error: "An error occurred while registering the user." });
    }
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "Invalid email or password" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid email or password" });

    const token = jwt.sign({ id: user._id, email: user.email }, "secretkey", { expiresIn: "1h" });
    res.json({ message: "Login successful", token, user: { firstName: user.firstName, lastName: user.lastName } });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "An error occurred during login" });
  }
});

app.get("/api/dashboard", authenticateToken, (req, res) => {
  res.json({ message: `Welcome to the dashboard, ${req.user.email}!` });
});

app.get("/", (req, res) => {
  res.send("Service is Live");
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
