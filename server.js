require("dotenv").config();

const express = require("express");
const argon2 = require("argon2");
const pool = require("./db");

const app = express();

app.use(express.json());
app.use(express.static("public"));

app.post("/api/register", async (req, res) => {
    try {
        const {username, email, password} = req.body;

        //1.validate input
        if(
            typeof username !== "string" ||
            typeof email !== "string" ||
            typeof password !== "string"
        ){
            return res.status(400).json({
                error: "Please provide a username, email, and password."
            });
        }
        const cleanUsername = username.trim();
        const cleanEmail = email.trim().toLowerCase();

        if(
            cleanUsername.length < 3 ||
            cleanUsername.length > 50 ||
            !/^[a-zA-Z0-9_]+$/.test(cleanUsername)
        ){
            return res.status(400).json({
                error: "Username must be 3-50 characters and contain only letters, numbers, and underscores."
            });
        }

        if(
            cleanEmail.length > 255 ||
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)
        ){
            return res.status(400).json({
                error: "Please provide a valid email address."
            });
        }

        if(
            password.length < 12 ||
            Buffer.byteLength(password, "utf8") > 1024
        ){
            return res.status(400).json({
                error: "Password must be at least 12 characters long."
            });
        }


        //2. Hash the passowrd
        const passwordHash = await argon2.hash(password);

        //3. Insert the account into MySQL
        await pool.execute(
            `INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)`,
            [cleanUsername, cleanEmail, passwordHash]
        );


        //4. Return a success response
        return res.status(201).json({
            message: "Account created successfully!"
        });

    } catch (error) {
        //Duplicate username or email (UNIQUE constraint)
        if(error.code === "ER_DUP_ENTRY") {
            return res.status(409).json({
                error: "That username or email is already registered."
            });
        }

        console.error("Registration error:", error.message);

        return res.status(500).json({
            error: "Something went wrong. Please try again."
        });
    }
});


const port = process.env.PORT || 3000;

app.listen(port, () =>{
    console.log(`Server running at http://localhost:${port}`);
});