#!/bin/sh

cat <<- EOF > /opt/bitnami/nginx/html/index.html
<!doctype HTML5>
<html>
  <head>
    <title>Hello, world</title>
  </head>
  <body>
    <h1>Hello, world</h1>
    <p>This server was set up by team ${team}</p>
  </body>
</html>
EOF