const express = require('express');
const axios = require('axios');
const app = express();

app.get('/proxy', (req, res) => {
    // Secure: request goes to hardcoded trusted host
    axios.get("https://api.trusted-partner.com")
        .then(response => res.send(response.data));
});
