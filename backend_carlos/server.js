const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');
const mysql = require('mysql2');
const session = require('express-session');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

const app = express();
const PORT = 5001;

// Configuración de la sesión
app.use(session({
  secret: 'secretKey',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // en producción con https poner true
}));

app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());


// --- 1. CONFIGURACIÓN BASE DE DATOS ---
const db = mysql.createPool({
    host: 'localhost',
    user: 'admin_node',      // Asegúrate que este usuario existe en MySQL
    password: 'password_seguro_123',
    database: 'hospital_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});


db.getConnection((err, connection) => {
    if (err) {
        console.error('❌ Error fatal: No se pudo conectar a MySQL.');
        console.error('   Causa:', err.code);
        console.error('   Verifica que XAMPP/MySQL esté encendido.');
    } else {
        console.log('✅ Conectado a MySQL (hospital_db)');
        connection.release();
    }
});

//Middleware
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login.html');
  }
  next();
}

function requireRole(roles) {
  return (req, res, next) => {
      if (req.session.userId && roles.includes(req.session.userId.tipo_usuario)) {
          next();
      } else {
          res.status(403).send('Acceso denegado');
      }
  };
}

// Ruta para obtener el tipo de usuario actual
app.get('/tipo-usuario', requireLogin, (req, res) => {
  res.json({ tipo_usuario: req.session.userId.tipo_usuario });
});

// Ruta protegida (Página principal después de iniciar sesión)
app.get('/', requireLogin, (_req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// Servir archivos estáticos (HTML)
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.post('/registrar', (req, res) => {
    const { nombre_usuario, password, codigo_acceso, nombre, apellido, email, fecha_nacimiento } = req.body;

    // 1. Validar datos básicos
    if (!nombre_usuario || !password || !codigo_acceso) {
        return res.status(400).send('Faltan datos obligatorios (Usuario, Contraseña o Código).');
    }

    // 2. Verificar Código de Acceso
    // USO DE 'db' EN LUGAR DE 'connection'
    const sqlCodigo = 'SELECT tipo_usuario FROM codigos_acceso WHERE codigo = ?';
    db.query(sqlCodigo, [codigo_acceso], (err, results) => {
        if (err) { console.error(err); return res.status(500).send('Error verificando código.'); }
        if (results.length === 0) return res.status(400).send('Código de acceso inválido.');

        const tipo_usuario = results[0].tipo_usuario;

        // 3. Verificar si el usuario ya existe
        const sqlExisteUser = 'SELECT 1 FROM usuarios WHERE nombre_usuario = ?';
        db.query(sqlExisteUser, [nombre_usuario], (err, existingUser) => {
            if (err) return res.status(500).send('Error verificando usuario.');
            if (existingUser.length > 0) return res.status(409).send('El nombre de usuario ya existe.');

            // 4. Encriptar contraseña
            bcrypt.hash(password, 10, (err, hashedPassword) => {
                if (err) return res.status(500).send('Error encriptando contraseña.');

                // 5. Insertar Usuario
                const sqlInsertUser = 'INSERT INTO usuarios (nombre_usuario, password_hash, tipo_usuario) VALUES (?, ?, ?)';
                db.query(sqlInsertUser, [nombre_usuario, hashedPassword, tipo_usuario], (err, resultUser) => {
                    if (err) { console.error(err); return res.status(500).send('Error creando usuario.'); }

                    const id_usuario = resultUser.insertId; // ID del usuario recién creado

                    // 6. Si es PACIENTE, guardar datos personales
                    if (tipo_usuario === 'paciente') {
                        if (!nombre || !apellido || !email || !fecha_nacimiento) {
                            return res.status(400).send('Faltan datos personales del paciente.');
                        }

                        const sqlInsertPaciente = 'INSERT INTO pacientes (id_usuario, nombre, apellido, email, fecha_nacimiento) VALUES (?, ?, ?, ?, ?)';
                        db.query(sqlInsertPaciente, [id_usuario, nombre, apellido, email, fecha_nacimiento], (err, resultPaciente) => {
                            if (err) { console.error(err); return res.status(500).send('Error guardando datos del paciente.'); }
                            
                            // Redirigir al login tras éxito
                            res.redirect('/login.html');
                        });

                    } else {
                        // Si es MEDICO o ADMIN, terminamos aquí
                        res.redirect('/login.html');
                    }
                });
            });
        });
    });
});





// Iniciar sesión
app.post('/login.html', (req, res) => {
    const { nombre_usuario, password } = req.body;

    // USO DE 'db' EN LUGAR DE 'connection'
    const sqlLogin = `
        SELECT u.*, p.id as id_paciente 
        FROM usuarios u 
        LEFT JOIN pacientes p ON u.id = p.id_usuario 
        WHERE u.nombre_usuario = ?`;

    db.query(sqlLogin, [nombre_usuario], async (err, results) => {
        if (err) { console.error(err); return res.status(500).send('Error en el servidor'); }
        
        if (results.length === 0) {
            return res.send('<h3 style="color:red">Usuario no encontrado</h3><a href="/login.html">Volver</a>');
        }

        const user = results[0];

        // Comparar contraseñas
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
            return res.send('<h3 style="color:red">Contraseña incorrecta</h3><a href="/login.html">Volver</a>');
        }

        // Guardar sesión
        req.session.userId = {
            id: user.id, // ID de la tabla usuarios
            nombre_usuario: user.nombre_usuario,
            tipo_usuario: user.tipo_usuario,
            paciente_id: user.id_paciente || null // ID de la tabla pacientes (si existe)
        };

        // Guardar la sesión explícitamente antes de redirigir (buena práctica)
        req.session.save(() => {
            res.redirect('/');
        });
    });
});

// Cerrar sesión
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login.html');
});

app.get('/session-data', (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'No autenticado' });
  }

  res.json({
    nombre_usuario: req.session.userId.nombre_usuario,
    pacienteId: req.session.userId.paciente_id || null
  });
});

// Ruta para que solo admin pueda ver todos los usuarios
app.get('/ver-usuarios', requireLogin, requireRole('admin'), (_req, res) => {
  connection.query('SELECT * FROM usuarios', (err, results) => {
    if (err) {
      return res.send('Error al obtener los datos.');
    }

  let html = `
    <html>
    <head>
      <link rel="stylesheet" href="/styles.css">
      <title>Usuarios</title>
    </head>
    <body>
      <h1>Usuarios Registrados</h1>
      <table>
        <thead>
          <tr>
            <th>id</th>
            <th>Nombre</th>
            <th>Contraseña Encriptada</th>
            <th>Tipo de usuario</th>
          </tr>
        </thead>
        <tbody>
  `;

  results.forEach(usuario => {
    html += `
      <tr>
        <td>${usuario.id}</td>
        <td>${usuario.nombre_usuario}</td>
        <td>${usuario.password_hash}</td>
        <td>${usuario.tipo_usuario}</td>
      </tr>
    `;
  });

  html += `
        </tbody>
      </table>
      <button onclick="window.location.href='/'">Volver</button>
    </body>
    </html>
  `;

  res.send(html);
});
});



// --- 2. MULTER ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = path.join(__dirname, 'uploads'); // Ruta absoluta
        if (!fs.existsSync(dir)) fs.mkdirSync(dir);
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + '-' + file.originalname);
    }
});

const upload = multer({ 
    storage: storage,
    fileFilter : (req, file, cb) => {
    // Tipos MIME permitidos
    const allowedMimes = ['audio/mpeg', 'audio/wav', 'audio/x-wav', 'audio/wave'];
    const ext = path.extname(file.originalname).toLowerCase();

    if (allowedMimes.includes(file.mimetype) || ext === '.mp3' || ext === '.wav') {
        cb(null, true);
    } else {
        cb(new Error('Formato no válido. Solo se permiten archivos MP3 y WAV.'), false);
    }
    },
    limits: { fileSize: 10 * 1024 * 1024 } 
});

// --- 3. MIDDLEWARE ---
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true })); 

// --- RUTAS ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/ver-pacientes', requireRole(['medico']), (req, res) => res.sendFile(path.join(__dirname, 'public', 'pacientes.html')));

app.get('/api/pacientes', (req, res) => {
    const query = `
        SELECT 
            d.id,              /* <--- ESTO ES LO IMPORTANTE: El ID del diagnóstico */
            p.nombre, 
            p.edad, 
            d.resultado_ia, 
            d.confianza, 
            d.fecha_analisis 
        FROM diagnosticos d
        INNER JOIN pacientes p ON d.paciente_id = p.id
        ORDER BY d.fecha_analisis DESC
    `;
    
    db.query(query, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

// --- 4. RUTA CRÍTICA: UPLOAD & CLASSIFY ---
app.post('/upload', upload.single('cancion'), (req, res) => {
    if (!req.file) return res.status(400).send('Falta archivo MP3.');

    const nombre = req.body.nombre || "Anónimo";
    const edad = req.body.edad || 0;
    const filePath = req.file.path; // Multer ya da la ruta completa
    const scriptPath = path.join(__dirname, 'classify.py');

    // --- CORRECCIÓN DE LA RUTA DE PYTHON ---
    // Intentamos buscar el venv, si no existe, usamos el python global del sistema
    let pythonExecutable;
    const venvPathWin = path.join(__dirname, 'venv', 'Scripts', 'python.exe');
    const venvPathLinux = path.join(__dirname, 'venv', 'bin', 'python');

    if (process.platform === 'win32' && fs.existsSync(venvPathWin)) {
        pythonExecutable = venvPathWin;
    } else if (process.platform !== 'win32' && fs.existsSync(venvPathLinux)) {
        pythonExecutable = venvPathLinux;
    } else {
        // FALLBACK: Si no encuentra la carpeta venv, usa el comando global
        console.warn("⚠️ Advertencia: No se encontró carpeta 'venv'. Usando Python global.");
        pythonExecutable = process.platform === 'win32' ? 'python' : 'python3';
    }

    console.log(`--- PROCESANDO ---`);
    console.log(`Script: ${scriptPath}`);
    console.log(`Python: ${pythonExecutable}`);

    const pythonProcess = spawn(pythonExecutable, [scriptPath, filePath]);

    let outputData = '';
    let errorData = '';

    // Error al INICIAR el proceso (ej. ruta de python mal)
    pythonProcess.on('error', (err) => {
        console.error("❌ ERROR AL SPAWN PYTHON:", err);
        errorData = `No se pudo iniciar Python. Verifica la ruta o instalación.\n${err.message}`;
    });

    pythonProcess.stdout.on('data', (data) => outputData += data.toString());
    pythonProcess.stderr.on('data', (data) => {
        errorData += data.toString();
        console.error(`PyLog: ${data}`);
    });

    pythonProcess.on('close', (code) => {
        console.log(`Python terminó con código: ${code}`);

        // CASO 1: Error crítico de Python (Crash o Spawn fallido)
        if (code !== 0 || errorData.includes("Traceback") || !outputData) {
            return res.status(500).send(`
                <div style="font-family: monospace; background: #ffe6e6; padding: 20px;">
                    <h2 style="color: red;">Error Técnico</h2>
                    <p>El análisis falló.</p>
                    <strong>Detalles:</strong>
                    <pre>${errorData || "El script no devolvió datos (posible error de librería faltante)."}</pre>
                    <a href="/">Volver</a>
                </div>
            `);
        }

        // CASO 2: Intentar leer JSON
        let result = null;
        try {
            result = JSON.parse(outputData.trim());
        } catch (e) {
            console.error("JSON Parse Error:", outputData);
            return res.status(500).send("Error interno: Respuesta de IA inválida.");
        }

        if (result.status === 'error') {
            return res.status(500).send(`<h3>Error IA:</h3> <p>${result.message}</p><a href="/">Volver</a>`);
        }

        // CASO 3: Éxito -> Guardar en BD
        const sqlPaciente = "INSERT INTO pacientes (nombre, edad) VALUES (?, ?)";
        db.query(sqlPaciente, [nombre, edad], (err, resP) => {
            if (err) {
                console.error("DB Error Paciente:", err);
                return res.status(500).send("Error guardando en base de datos.");
            }

            const pid = resP.insertId;
            const sqlDiag = `INSERT INTO diagnosticos (paciente_id, ruta_audio, resultado_ia, confianza, ciclos_detectados) VALUES (?, ?, ?, ?, ?)`;
            
            db.query(sqlDiag, [pid, req.file.path, result.class, result.confidence, result.cycles], (err, resD) => {
                if (err) console.error("DB Error Diagnóstico:", err);

                // HTML RESPUESTA
                const isNormal = result.class.toLowerCase() === 'normal';
                const color = isNormal ? '#28a745' : '#dc3545';
                const icon = isNormal ? '💚' : '⚠️';

                res.send(`
                    <!DOCTYPE html>
                    <html lang="es">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>Resultados</title>
                        <link rel="stylesheet" href="styles.css">
                        <style>
                            body { text-align: center; padding: 40px; }
                            .stats { background: #f8f9fa; padding: 15px; border-left: 5px solid ${color}; text-align: left; margin: 20px auto; max-width: 400px; }
                        </style>
                    </head>
                    <body>
                        <div class="container">
                        <div class="card" style="max-width: 600px; margin: 0 auto;">
                            <h1>${icon} ${isNormal ? 'NORMAL' : 'ANOMALÍA'}</h1>
                            <p><strong>Paciente:</strong> ${nombre} (${edad} años)</p>
                            <div class="stats">
                                <p>🔍 Diagnóstico: <strong>${result.class}</strong></p>
                                <p>📊 Confianza: ${result.confidence}%</p>
                                <p>💓 Latidos: ${result.cycles}</p>
                            </div>
                            <small style="color:green">💾 Guardado ID #${pid}</small>
                            <br><br>
                            <a href="/" class="btn-upload" style="text-decoration:none">Nuevo Análisis</a>
                            <br><br>
                            <a href="/ver-pacientes" style="color:#666">Ver Historial</a>
                        </div>
                        </div>
                    </body>
                    </html>
                `);
            });
        });
    });
});

// 2. RUTA PARA SERVIR LA VISTA DE DETALLE
app.get('/ver-detalle', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'detalle.html'));
});

// 3. API PARA OBTENER UN DIAGNÓSTICO ESPECÍFICO POR ID
app.get('/api/diagnostico/:id', (req, res) => {
    const id = req.params.id;
    
    const query = `
        SELECT d.*, p.nombre, p.edad 
        FROM diagnosticos d
        JOIN pacientes p ON d.paciente_id = p.id
        WHERE d.id = ?
    `;

    db.query(query, [id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(404).json({ error: 'No encontrado' });

        const diag = results[0];

        // --- MEJORA DE ROBUSTEZ ---
        // 1. Extraemos el nombre del archivo de forma segura (funciona en Windows y Linux)
        // Esto toma lo que está después de la última barra '/' o '\'
        const filename = diag.ruta_audio.split(/[\\/]/).pop();
        
        // 2. Construimos la URL pública
        diag.url_web = `/uploads/${filename}`;

        // 3. (Opcional) Le decimos al frontend qué tipo de archivo es
        diag.tipo_archivo = filename.endsWith('.wav') ? 'WAV' : 'MP3';

        res.json(diag);
    });
});

// ... (Tus códigos anteriores) ...

// ====================================================
// ZONA ADMINISTRADOR: ENTRENAMIENTO
// ====================================================

// 1. Configuración Multer especial para la carpeta DATA
const storageData = multer.diskStorage({
    destination: (req, file, cb) => {
        // Asegurar que la carpeta data existe
        const dir = path.join(__dirname, 'data');
        if (!fs.existsSync(dir)) fs.mkdirSync(dir);
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        // TRUCO: Renombramos el archivo con la etiqueta al principio
        // Ejemplo: "normal_17623123_audio.mp3"
        const etiqueta = req.body.etiqueta || "unknown"; 
        
        // Usamos un número aleatorio extra para evitar colisiones si se suben varios al mismo tiempo
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname).toLowerCase();
        
        const nuevoNombre = `${etiqueta}_${uniqueSuffix}${ext}`;
        cb(null, nuevoNombre);
    }
});

// Filtro para aceptar MP3 y WAV
const uploadData = multer({ 
    storage: storageData,
    fileFilter: (req, file, cb) => {
        const allowed = ['.mp3', '.wav'];
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowed.includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error('Solo archivos .mp3 y .wav permitidos'), false);
        }
    }
});

// 2. Ruta para subir MÚLTIPLES archivos de entrenamiento (Solo Admin)
// CAMBIO CLAVE: .array('audio_entrenamiento') en lugar de .single()
app.post('/api/admin/upload-data', requireLogin, requireRole(['admin']), uploadData.array('audio_entrenamiento'), (req, res) => {
    
    if (!req.files || req.files.length === 0) {
        return res.status(400).json({ error: 'No se subieron archivos.' });
    }

    const count = req.files.length;
    console.log(`📂 Admin subió ${count} archivos con etiqueta: ${req.body.etiqueta}`);

    res.json({ 
        success: true, 
        message: `Se guardaron ${count} archivos correctamente para entrenamiento.` 
    });
});

// 3. Ruta para EJECUTAR EL REENTRENAMIENTO (Solo Admin)
app.post('/api/admin/retrain', requireLogin, requireRole(['admin']), (req, res) => {
    
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Transfer-Encoding', 'chunked');

    const scriptPath = path.join(__dirname, 'train.py');
    
    let pythonExecutable;
    const venvPathWin = path.join(__dirname, 'venv', 'Scripts', 'python.exe');
    const venvPathLinux = path.join(__dirname, 'venv', 'bin', 'python');

    if (process.platform === 'win32' && fs.existsSync(venvPathWin)) {
        pythonExecutable = venvPathWin;
    } else if (process.platform !== 'win32' && fs.existsSync(venvPathLinux)) {
        pythonExecutable = venvPathLinux;
    } else {
        pythonExecutable = process.platform === 'win32' ? 'python' : 'python3';
    }

    res.write(`🚀 Iniciando motor de IA...\n`);
    res.write(`📂 Ejecutando: ${scriptPath}\n`);

    const pythonProcess = spawn(pythonExecutable, [scriptPath]);

    pythonProcess.stdout.on('data', (data) => {
        res.write(data.toString());
    });

    pythonProcess.stderr.on('data', (data) => {
        res.write(`[LOG]: ${data.toString()}`);
    });

    pythonProcess.on('close', (code) => {
        if (code === 0) {
            res.write(`\n✅ ¡ENTRENAMIENTO COMPLETADO CON ÉXITO!\n`);
            res.write(`El nuevo modelo 'heart_sound_model.pkl' ya está activo.`);
        } else {
            res.write(`\n❌ ERROR FATAL: El proceso terminó con código ${code}`);
        }
        res.end(); 
    });
});

// Ruta para acceder al panel (HTML)
app.get('/admin', requireLogin, requireRole(['admin']), (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.use((err, req, res, next) => {
    if (err) return res.status(500).send(`Error Servidor: ${err.message}`);
    next();
});

app.listen(PORT, () => {
    console.log(`🚀 Servidor en ${PORT}`);
});