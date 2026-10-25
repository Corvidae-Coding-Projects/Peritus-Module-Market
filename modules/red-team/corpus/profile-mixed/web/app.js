const form = document.querySelector("#echo");
const result = document.querySelector("#result");

form.addEventListener("submit", (event) => {
  event.preventDefault();
  result.textContent = new FormData(form).get("message") ?? "";
});
