require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cloudinary = require("cloudinary").v2;
const multer = require("multer");
const { CloudinaryStorage } = require("multer-storage-cloudinary");

const app = express();
app.use(express.json());
app.use(cors());

// MongoDB Connection
const mongoURI = process.env.MONGO_URI;
mongoose
  .connect(mongoURI, {})
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.error(err));

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Configure Multer Storage with Cloudinary
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "user_images", // Folder name in Cloudinary
    allowed_formats: ["jpg", "jpeg", "png"], // Allow only specific formats
  },
});
const upload = multer({ storage });

// User Schema
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  age: { type: Number, required: true },
  mobile: { type: String, required: true },
  gender: { type: String, required: true },
  profileImage: { type: String }, // Store image URL
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

// Signup Route with Image Upload
app.post("/api/signup", upload.single("image"), async (req, res) => {
  const { firstName, lastName, email, password, age, mobile, gender } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      age,
      mobile,
      gender,
      profileImage: req.file ? req.file.path : null, // Save image URL from Cloudinary
    });
    await newUser.save();
    res.status(201).json({ message: "User registered successfully!" });
  } catch (error) {
    if (error.code === 11000) {
      res.status(400).json({ error: "Email already exists!" });
    } else {
      console.error(error);
      res.status(500).json({ error: "An error occurred while registering the user." });
    }
  }
});

// Login Route
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "Invalid email or password" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid email or password" });

    const token = jwt.sign({ id: user._id, email: user.email }, "secretkey", { expiresIn: "1h" });
    res.json({
      message: "Login successful",
      token,
      user: { firstName: user.firstName, lastName: user.lastName, profileImage: user.profileImage },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "An error occurred during login" });
  }
});

// Protected Dashboard Route
app.get("/api/dashboard", authenticateToken, (req, res) => {
  res.json({ message: `Welcome to the dashboard, ${req.user.email}!` });
});

// Image Upload Route
app.post("/api/upload", upload.single("image"), (req, res) => {
  try {
    res.status(200).json({ imageUrl: req.file.path });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Image upload failed" });
  }
});

// Root Route
app.get("/", (req, res) => {
  res.send("Service is Live");
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
