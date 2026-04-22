const db = require("../config/db");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken")

const pepper = process.env.PEPPER;
const secret = process.env.JWT_SECRET

module.exports = {
  // ----------------------------------------------------------
  // POST /api/auth/login
  // ----------------------------------------------------------
  login: async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email et mot de passe requis" });
    }

    try {
      const sql = "SELECT * FROM users WHERE email = ?";

      db.query(sql, [email], async (err, results) => {
        if (err) {
          return res.status(500).json({ error: err.message, query: query });
        }

        if (results.length === 0) {
          return res
            .status(401)
            .json({ error: "Email ou mot de passe incorrect" });
        }

        const user = results[0];
        const spicyPassword = password + pepper
        const isMatch = await bcrypt.compare(spicyPassword, user.password);
        const payload = { sub: user.id, role: user.role}

        if (!isMatch) {
          return res
            .status(401)
            .json({ error: "Email ou mot de passe incorrect" });
        }

        delete user.password;

        const token = jwt.sign(payload, secret, {
          expiresIn: '60m'
        })

        console.log("Access Token: ", token)
        res.redirect('/')
      });

    } catch (error) {
      res.status(401).json({ error: "Email ou mot de passe incorrect" });
    }
  },

  // ----------------------------------------------------------
  // POST /api/auth/register
  // ----------------------------------------------------------
  register: async (req, res) => {
    const { username, email, password, address, photo } = req.body;

    if (!username || !email || !password || !address) {
      return res.status(400).json({ error: "Des champs ne sont pas remplis" });
    }

    try {

      const spicyPassword = password + pepper
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(spicyPassword, salt);

      const sql =
        "INSERT INTO users (username, email, password, address, photo_path) VALUES (?, ?, ?, ?, ?)";
      const values = [username, email, hashedPassword, address, photo];

      db.query(sql, values, (err, results) => {
        if (err) {
          return res.status(500).json({ error: err.message, query: query });
        }

        console.log("Inscription réussie")
        res.redirect('/')
      });
    } catch (error) {
      res.status(500).json({ error: "Error lors du hashage" });
    }
  },
};
