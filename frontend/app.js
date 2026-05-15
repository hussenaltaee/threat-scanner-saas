const API = "http://127.0.0.1:8000";

async function login() {
  let res = await fetch(API + "/login", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      username: document.getElementById("u").value,
      password: document.getElementById("p").value
    })
  });

  let data = await res.json();

  if (data.access_token) {
    localStorage.setItem("token", data.access_token);
    window.location = "dashboard.html";
  } else {
    alert("Login failed");
  }
}

async function scan() {
  let token = localStorage.getItem("token");

  let res = await fetch(API + "/scan", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token
    },
    body: JSON.stringify({
      target: document.getElementById("target").value
    })
  });

  let data = await res.json();
  document.getElementById("out").innerText =
    JSON.stringify(data, null, 2);
}