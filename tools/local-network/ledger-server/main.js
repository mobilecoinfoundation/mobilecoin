const express = require('express');
var { argv } = require('yargs')
    .option("b", {
        alias: "baseDir",
        describe: "The base directory to serve files from.",
        demandOption: "The base directory is required.",
        type: "string",
        nargs: 1,
    })
    .option("p", {
        alias: "port",
        describe: "The port to listen on.",
        demandOption: "The port is required.",
        type: "number",
        nargs: 1,
        default: 6060,
    })

const app = express();

const { baseDir, port } = argv;

app.get('/*', (req, res) => {
    console.log(req.url);

    res.sendFile(req.path, { root: baseDir });
});

app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`);
});