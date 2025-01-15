const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");

// Initialize Express App
const app = express();
app.use(express.json());

// Allow all origins for CORS
app.use(cors());

// MongoDB Connection
const mongoURI =
  "mongodb+srv://ishapatilgenai:mxspMbPLIDVJWem0@test-db.ybesv.mongodb.net/?retryWrites=true&w=majority&appName=test-db";
mongoose
  .connect(mongoURI, {})
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

// Routes
app.post("/api/signup", async (req, res) => {
  const { firstName, lastName, email, password, age, mobile, gender } = req.body;

  try {
    const newUser = new User({ firstName, lastName, email, password, age, mobile, gender });
    await newUser.save();
    res.status(201).json({ message: "User registered successfully!" });
  } catch (error) {
    if (error.code === 11000) {
      res.status(400).json({ error: "Email already exists!" });
    } else {
      console.log(error);
      res.status(500).json({ error: "An error occurred while registering the user." });
    }
  }
});

app.get('/', (req,res)=>{
  res.send("Service is Live");
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
