const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/preview', (req, res) => {
  const filename = req.query.filename;
  exec(`cat ${filename}`, (_error, stdout) => res.send(stdout));
});

app.delete('/admin/roles/:id', (req, res) => {
  res.json({ deleted: req.params.id });
});
