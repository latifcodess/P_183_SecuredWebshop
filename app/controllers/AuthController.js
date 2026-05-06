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
          return res.status(500).json({ error: err.message });
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
          expiresIn: '30m'
        })

        const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });
        
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
        db.query(
          "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
          [user.id, refreshToken, expiresAt]
        );

        console.log("Access Token: ", token)
        
        // stock le token dans un cookie
        res.cookie('token', token, {
          httpOnly: true,
          secure: true,
          maxAge: 30 * 60 * 1000
        });

        res.cookie('refreshToken', refreshToken, {
          httpOnly: true,
          secure: true,
          maxAge: 7 * 24 * 60 * 60 * 1000
        });
        
        res.redirect('/');
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

  refresh: async (req, res) => {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({ error: "Refresh token manquant" });
    }

    try {
      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

      db.query(
        "SELECT * FROM refresh_tokens WHERE token = ? AND expires_at > NOW()", [refreshToken],
        (err, results) => {
          if (err || results.length === 0) {
            return res.status(401).json({ error: "Refresh token invalide" });
          }
          
          const payload = { sub: decoded.sub, role: decoded.role };
          const newAccessToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '30m' });

          res.cookie('token', newAccessToken, {
            httpOnly: true,
            secure: true,
            maxAge: 30 * 60 * 1000
          });

          res.status(200).json({ message: "Token renouvelé" });
        }
      );
    } catch (err) {
      return res.status(401).json({ error: "Refresh token expiré ou invalide" });
    }
  },

  logout: (req, res) => {
    const refreshToken = req.cookies.refreshToken;

    db.query("DELETE FROM refresh_tokens WHERE token = ?", [refreshToken]);

    res.clearCookie('token');
    res.clearCookie('refreshToken');

    res.redirect('/login');
  }
};
