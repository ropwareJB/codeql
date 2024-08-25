
var express = require('express');

var app = express();

// Variant 1: Classic `import` call
app.get('/some/path', async function(req, res) {
    // BAD: loading a module based on un-sanitized query parameters
    const { default: yy } = await import(req.params.userinput);
    return yy;
});

// Variant 2: Use of script.js
// https://github.com/ded/script.js
var scriptjs = require('scriptjs');
app.get('/some/other/path', async function(req, res) {
    // BAD
    scriptjs(req.params.userinput, function() {});
    // BAD
    scriptjs([req.params.userinput, "some-static"], function() {});
});


