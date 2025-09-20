const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');
const app = express();
const port = 9000;

// Middleware para analizar el cuerpo de las solicitudes JSON
app.use(express.json());

// Servir archivos estáticos desde la carpeta 'public'
app.use(express.static(path.join(__dirname, 'public')));

// Configurar para confiar en proxies si es necesario
app.set('trust proxy', true);

// Simulación de base de datos en memoria
const users = [
  { id: 1, username: 'usuario1', password: bcrypt.hashSync('contrasena1', 10) },
  { id: 2, username: 'usuario2', password: bcrypt.hashSync('secreto2', 10) },
];

// Clave secreta (en producción, usa variables de entorno)
const secretKey = process.env.JWT_SECRET || 'miClaveSecretaSuperSegura';

// Función para generar un JWT
function generateToken(user) {
  const payload = {
    userId: user.id,
    username: user.username,
  };
  return jwt.sign(payload, secretKey, { expiresIn: '1h' });
}

// Middleware para verificar el JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

  if (!token) {
    return res.status(401).sendFile(path.join(__dirname, 'public', 'cerrado.html'), {
      headers: { 'X-Message': 'Acceso restringido por no tener token' }
    });
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.status(403).sendFile(path.join(__dirname, 'public', 'cerrado.html'), {
        headers: { 'X-Message': 'Acceso restringido por token inválido' }
      });
    }
    req.user = user;
    res.setHeader('X-Message', 'Acceso concedido por tener el token');
    next();
  });
}

// Ruta para el inicio de sesión
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Obtener la IP del cliente
  let clientIp = req.headers['x-forwarded-for'] || req.ip || req.socket.remoteAddress;

  // Limpiar formato IPv6 si es necesario
  if (clientIp && clientIp.startsWith('::ffff:')) {
    clientIp = clientIp.replace('::ffff:', '');
  }

  if (!clientIp) {
    console.error('No se pudo obtener la IP del cliente');
    return res.status(500).json({ error: 'No se pudo obtener la IP' });
  }

  console.log(`Solicitud desde IP: ${clientIp}, Usuario: ${username}`);

  // Buscar al usuario
  const user = users.find(u => u.username === username);

  // Verificar credenciales
  if (user && bcrypt.compareSync(password, user.password)) {
    const token = generateToken(user);
    res.json({ token, ip: clientIp });
  } else {
    res.status(401).json({ message: 'Credenciales inválidas' });
  }
});

// Ruta pública
app.get('/abierto', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'abierto.html'));
});

// Ruta protegida
app.get('/cerrado', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'cerrado.html'));
});

app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});