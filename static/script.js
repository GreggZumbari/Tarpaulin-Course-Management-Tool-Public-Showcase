'use strict';

document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("login-form");
    if (form) {
        form.addEventListener("submit", handleLogin);
    }
});

function handleLogin(event) {
    event.preventDefault(); // Block default form POST

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    fetch("/users/login", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ username, password })
    })
    .then(async response => {
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.message || "Login failed");
        }
        console.log("Success:", data);
        alert("Login successful!");
        // Maybe store the token or redirect here
    })
    .catch(error => {
        console.error("Error:", error);
        alert("Login failed: " + error.message);
    });
}

window.addEventListener('load', function () {
    console.log("Hello World!");
});