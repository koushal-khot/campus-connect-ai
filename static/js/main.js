// Open/close <dialog> modals via data attributes.
document.querySelectorAll("[data-open]").forEach((btn) => {
  btn.addEventListener("click", () => {
    const dlg = document.getElementById(btn.dataset.open);
    if (dlg && typeof dlg.showModal === "function") dlg.showModal();
  });
});

document.querySelectorAll("dialog").forEach((dlg) => {
  dlg.querySelectorAll("[data-close]").forEach((b) =>
    b.addEventListener("click", () => dlg.close())
  );
  // Click on the backdrop closes the dialog.
  dlg.addEventListener("click", (e) => {
    if (e.target === dlg) dlg.close();
  });
});

// Register form: show only the fields that match the chosen role.
const roleSelect = document.getElementById("role-select");
const yearField = document.getElementById("year-field");
const adminField = document.getElementById("admin-field");
if (roleSelect && yearField && adminField) {
  const adminInput = adminField.querySelector("input");
  const sync = () => {
    yearField.hidden = roleSelect.value !== "student";
    adminField.hidden = roleSelect.value !== "admin";
    adminInput.required = roleSelect.value === "admin";
  };
  roleSelect.addEventListener("change", sync);
  sync();
}

// Fade flash messages after a few seconds.
document.querySelectorAll(".flash").forEach((el) =>
  setTimeout(() => el.classList.add("gone"), 4500)
);
