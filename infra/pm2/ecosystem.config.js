module.exports = {
  apps: [
    {
      name: "devopsec-backend",
      cwd: "/var/www/devopsec/backend",
      script: "dist/server.js",
      instances: 1,
      exec_mode: "fork",
      env: {
        NODE_ENV: "production",
        PORT: 4000
      }
    }
  ]
};
