const express = require('express');
const axios = require('axios');
const app = express();

app.get('/proxy', (req, res) => {
    const url = req.query.url;
    axios.get(url)
        .then(response => res.send(response.data))
        .catch(err => res.status(500).send(err.message));
});
