// =============================================================
// Middleware d'authentification
// =============================================================

const jwt    = require('jsonwebtoken');
const secret = process.env.JWT_SECRET;

module.exports = (_req, _res, next) => {
    next();
};

const verifyToken = (req, res, next) => {
  // extrait le token du cookie
  const token = req.cookies?.token
  
  // verifie que le token éxiste
  if (!token) {
    return res.status(401).json({ error: "Token manquant" });
  } 

  try {
    // verifie la validité du token et l'expiration
    const decoded = jwt.verify(token, secret);
    // décompose le token pour extraire le sub et le role
    req.user = decoded;
    next();
    // gestion des erreurs
  } catch (err) {
    return res.status(403).json({ error: "Token invalide ou expiré" });
  }
};

const requireRole = (...roles) => (req, res, next) => {
  // verifie que le tableaux roles contient le role requis
  if (!roles.includes(req.user?.role)) {
    return res.status(403).json({ error: "Accès interdit" });
  }
  next();
};

module.exports = { verifyToken, requireRole }