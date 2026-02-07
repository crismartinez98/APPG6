require('dotenv').config(); // Importante, antes de usar process.env

const express = require('express');
const bodyParser = require('body-parser');
const sql = require('mssql');
const validator = require('validator');
const xss = require('xss');

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.urlencoded({ extended: true }));

// ===================
// Configuración Azure SQL
// ===================
const config = {
    server: process.env.DB_SERVER,
    database: process.env.DB_NAME,
    authentication: {
        type: 'default',
        options: {
            userName: process.env.DB_USER,
            password: process.env.DB_PASS
        }
    },
    options: {
        encrypt: true,
        trustServerCertificate: false
    }
};

// ===================
// FORMULARIO
// ===================
app.get('/', (req, res) => {
    res.send(`
        <h1>Comentarios</h1>
        <form method="POST" action="/comentario">
            <input type="text" name="nombres" placeholder="Nombres" required><br><br>
            <input type="text" name="apellidos" placeholder="Apellidos" required><br><br>
            <input type="email" name="email" placeholder="Email" required><br><br>
            <input type="number" name="edad" placeholder="Edad" required><br><br>
            <input type="text" name="direccion" placeholder="Dirección" required><br><br>
            <textarea name="comentario" placeholder="Escribe tu comentario" required></textarea><br><br>
            <button type="submit">Enviar</button>
        </form>
    `);
});

// ===================
// REGISTRO SEGURO
// ===================
app.post('/comentario', async (req, res) => {
    let { nombres, apellidos, email, edad, direccion, comentario } = req.body;

    // ---------- VALIDACIÓN ----------
    if (
        !nombres || !apellidos || !email || !edad || !direccion || !comentario
    ) {
        return res.status(400).send("Todos los campos son obligatorios.");
    }

    if (!validator.isEmail(email)) {
        return res.status(400).send("Email no válido.");
    }

    if (!validator.isInt(edad.toString(), { min: 1, max: 120 })) {
        return res.status(400).send("Edad no válida.");
    }

    // Rechazo explícito de scripts
    const combinado = `${nombres} ${apellidos} ${direccion} ${comentario}`.toLowerCase();
    if (combinado.includes("<script")) {
        return res.status(400).send("Entrada rechazada por contener código malicioso.");
    }

    // ---------- SANITIZACIÓN (ANTI XSS) ----------
    nombres = xss(nombres.trim());
    apellidos = xss(apellidos.trim());
    email = xss(email.trim().toLowerCase());
    direccion = xss(direccion.trim());
    comentario = xss(comentario.trim());

    try {
        const pool = await sql.connect(config);

        // ---------- CONSULTA PARAMETRIZADA (ANTI SQLi) ----------
        await pool.request()
            .input('nombres', sql.NVarChar(100), nombres)
            .input('apellidos', sql.NVarChar(100), apellidos)
            .input('email', sql.NVarChar(150), email)
            .input('edad', sql.Int, edad)
            .input('direccion', sql.NVarChar(200), direccion)
            .input('comentario', sql.NVarChar(300), comentario)
            .query(`
                INSERT INTO SecureFeedback
                (Nombres, Apellidos, Email, Edad, Direccion, Comentario)
                VALUES
                (@nombres, @apellidos, @email, @edad, @direccion, @comentario)
            `);

        res.send("Comentario guardado de forma segura ✅");

    } catch (err) {
        console.error(err);
        res.status(500).send("Error en el servidor ❌");
    }
});

// ===================
app.listen(port, () =>
    console.log(`App corriendo en puerto ${port}`)
);