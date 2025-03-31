const express = require('express');
const bodyParser = require("body-parser");
const { spawn } = require('child_process');

const app = express();

app.use(express.json()); // Middleware to parse JSON request bodies

app.use((req, res, next) => {
    console.log(`Received ${req.method} request at ${req.url}`);
    next();
});

// app.use((req, res, next) => {
//    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
//    next(); // Pass control to the next handler
// });

// Middleware to parse JSON and URL-encoded data
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Serve the HTML form
app.get("/", (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Submit Quote</title>
        </head>
        <body>
            <h1>Submit Your Quote</h1>
            <form method="POST" action="/dcap-tools/quote-parse">
                <label for="quote">Quote:</label><br>
                <textarea id="quote" name="quote" rows="30" style="width: 100%;" required></textarea><br>
                <button type="submit">Submit</button>
            </form>
        </body>
        </html>
    `);
});

app.post('/quote-parse', (req, res) => {
    const inputParam = req.body.quote; // Expecting { "quote": "some_value" }

    if (!inputParam) {
        return res.status(400).json({ error: 'Missing required parameter: quote' });
    }

    // Run external tool with the input parameter
    const process = spawn('./dcap_collateral_tool', [inputParam]);

    let output = '';
    process.stdout.on('data', (data) => {
        output += data.toString();
    });

    process.stderr.on('data', (data) => {
        console.error(`Error: ${data}`);
    });

    process.on('close', (code) => {
        if (code === 0) {
            try {
                res.json(JSON.parse(output)); // Send parsed JSON response
            } catch (error) {
                res.status(500).json({ error: 'Invalid JSON output from tool' });
            }
        } else {
            res.status(500).json({ error: `Process exited with code ${code}` });
        }
    });
});

app.listen(3000, () => console.log('Server running on port 3000'));

