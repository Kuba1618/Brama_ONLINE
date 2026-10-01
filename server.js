const express = require("express");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

const app = express();

const PORT = process.env.PORT || 10000;

const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

const ESP_TOKEN = process.env.ESP_TOKEN;
const JWT_SECRET = process.env.JWT_SECRET;

const GMAIL_USER = process.env.GMAIL_USER;
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD;
const GMAIL_TO = process.env.GMAIL_TO;

let pendingCommand = false;

// przechowywanie aktualnego kodu 2FA
let verificationCode = null;
let verificationExpires = null;

const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    family: 4,
    auth: {
        user: GMAIL_USER,
        pass: GMAIL_APP_PASSWORD
    }
});


app.use(express.json());
app.use(express.static("public"));


// =============================
// LOGOWANIE - ETAP 1
// =============================

app.post("/api/login", async (req, res) => {

    const { username, password } = req.body;

    if (
        username !== ADMIN_USER ||
        password !== ADMIN_PASSWORD
    ) {
        return res.status(401).json({
            success: false,
            message: "Nieprawidłowy login lub hasło"
        });
    }

    // generowanie kodu 6-cyfrowego
    const code = Math.floor(100000 + Math.random() * 900000).toString();

    verificationCode = code;

    // kod ważny 5 minut
    verificationExpires = Date.now() + 5 * 60 * 1000;

    try {

        await transporter.sendMail({
            from: GMAIL_USER,
            to: GMAIL_TO,
            subject: "Kod logowania - Sterowanie bramą",
            text: `Twój kod logowania: ${code}\n\nKod jest ważny przez 5 minut.`
        });

        console.log("Wysłano kod 2FA");

        res.json({
            success: true,
            requiresCode: true
        });

    } catch (error) {

        console.error("Błąd wysyłania e-maila:", error);

        res.status(500).json({
            success: false,
            message: "Nie udało się wysłać kodu"
        });
    }
});


// =============================
// WERYFIKACJA KODU 2FA
// =============================

app.post("/api/verify-code", (req, res) => {

    const { code } = req.body;

    if (!verificationCode || !verificationExpires) {
        return res.status(401).json({
            success: false,
            message: "Brak aktywnego kodu"
        });
    }

    if (Date.now() > verificationExpires) {

        verificationCode = null;
        verificationExpires = null;

        return res.status(401).json({
            success: false,
            message: "Kod wygasł"
        });
    }

    if (code !== verificationCode) {

        return res.status(401).json({
            success: false,
            message: "Nieprawidłowy kod"
        });
    }

    // kod wykorzystany
    verificationCode = null;
    verificationExpires = null;

    const token = jwt.sign(
        { username: ADMIN_USER },
        JWT_SECRET,
        { expiresIn: "7d" }
    );

    res.json({
        success: true,
        token: token
    });
});


// =============================
// SPRAWDZENIE TOKENU
// =============================

function checkUser(req, res, next) {

    const auth = req.headers.authorization;

    if (!auth) {
        return res.status(401).json({
            message: "Brak autoryzacji"
        });
    }

    const token = auth.replace("Bearer ", "");

    try {

        jwt.verify(token, JWT_SECRET);

        next();

    } catch {

        return res.status(401).json({
            message: "Nieprawidłowy token"
        });
    }
}


// =============================
// OTWARCIE BRAMY
// =============================

app.post("/api/open", checkUser, (req, res) => {

    pendingCommand = true;

    console.log("Oczekująca komenda OTWÓRZ BRAMĘ");

    res.json({
        success: true,
        message: "Komenda wysłana do ESP32"
    });
});


// =============================
// ESP32 PYTA O KOMENDĘ
// =============================

app.get("/api/command", (req, res) => {

    const token = req.headers["x-esp-token"];

    if (token !== ESP_TOKEN) {

        return res.status(401).json({
            message: "Brak dostępu"
        });
    }

    if (pendingCommand) {

        pendingCommand = false;

        console.log("Komenda przekazana do ESP32");

        return res.json({
            command: "OPEN"
        });
    }

    res.json({
        command: "NONE"
    });
});


// =============================
// STATUS
// =============================

app.get("/api/status", checkUser, (req, res) => {

    res.json({
        online: true,
        pending: pendingCommand
    });
});


// =============================
// START
// =============================

app.listen(PORT, "0.0.0.0", () => {

    console.log(`Serwer działa na porcie ${PORT}`);

});