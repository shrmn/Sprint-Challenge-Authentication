const axios = require("axios");
const bcrypt = require("bcryptjs");
const db = require("../database/dbConfig");
const jwt = require('jsonwebtoken');

const { authenticate } = require("../auth/authenticate");

module.exports = server => {
  server.post("/api/register", register);
  server.post("/api/login", login);
  server.get("/api/jokes", authenticate, getJokes);
};

async function register(req, res) {
  const creds = req.body;
  const { username, password } = creds;

  if (!username || !password) {
    return res.status(400).json({
      message: `Both a username and a password are required to register.`
    });
  }

  const hash = bcrypt.hashSync(password, 5);
  req.body.password = hash;

  try {
    const [id] = await db("users").insert(creds);

    const newUser = db("users")
      .select("id", "username")
      .where({ id })
      .first();
    
    const token = generateToken(newUser);

    res.status(201).json(newUser, token);
  } catch (error) {
    res.status(500).json({
      error: `Error while registering user: ${error}`
    });
  }
}

async function login(req, res) {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      message: `Both a username and a password are required to log in.`
    });
  }

  try {
    const user = await db("users")
      .where({ username })
      .first();
    if (user && bcrypt.compareSync(password, user.password)) {
      const token = generateToken(user);
      res.status(200).json({ message: `Successfully logged in`, token})
    } else {
      res.status(401).json({
        message: `Username or password incorrect. Please try again.`
      });
    }
  } catch (error) {
    res.status(500).json({
      error: `Error while logging in: ${error}`
    });
  };
};

function getJokes(req, res) {
  const requestOptions = {
    headers: { accept: "application/json" }
  };

  axios
    .get("https://icanhazdadjoke.com/search", requestOptions)
    .then(response => {
      res.status(200).json(response.data.results);
    })
    .catch(err => {
      res.status(500).json({ message: "Error Fetching Jokes", error: err });
    });
}

function generateToken({user}) {
  const payload = {
    subject: user.id,
    username: user.username
  };

  const secret = process.env.JWT_SECRET ||
  'add a .env file to root of project with the JWT_SECRET variable';

  const options = {
    expiresIn = '30m'
  };

  return jwt.sign(payload, secret, options)
};
