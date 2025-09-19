const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const app = express();
const port = 9000;

// Middleware para analizar el cuerpo de las solicitudes JSON
app.use(express.json());

// ¡IMPORTANTE! En una aplicación real, usa una base de datos.
// Aquí simulamos una base de datos en memoria.
const users = [
  { id: 1, username: 'usuario1', password: bcrypt.hashSync('contrasena1', 10) },
  { id: 2, username: 'usuario2', password: bcrypt.hashSync('secreto2', 10) },
];

// ¡IMPORTANTE! Guarda esta clave secreta en un lugar seguro (variables de entorno, etc.).
const secretKey = 'miClaveSecretaSuperSegura';

// Función para generar un JWT
function generateToken(user) {
  // Podrías incluir más información relevante del usuario en el payload
  const payload = {
    userId: user.id,
    username: user.username,
    // Otros datos del usuario si es necesario
  };
  return jwt.sign(payload, secretKey, { expiresIn: '1h' });
}

// Middleware para verificar el JWT en rutas protegidas
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

  if (token == null) {
    return res.sendStatus(401); // No autorizado
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.sendStatus(403); // Prohibido (token inválido)
    }
    req.user = user; // Agrega la información del usuario decodificada al objeto de la solicitud
    next(); // Continúa con la siguiente middleware o ruta
  });
}

// Ruta para el inicio de sesión
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
console.log(req.body.username);
  // 1. Buscar al usuario en la base de datos (simulada)
  const user = users.find(u => u.username === username);

  // 2. Verificar si el usuario existe y la contraseña es correcta
  if (user && bcrypt.compareSync(password, user.password)) {
    // 3. Generar un JWT
    const token = generateToken(user);
    // 4. Enviar el JWT al cliente
    res.json({ token: token });
  } else {
    res.status(401).json({ message: 'Credenciales inválidas' });
  }
});

// Ruta protegida (requiere autenticación con JWT)
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'Esta ruta está protegida', user: req.user });
});

app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});
