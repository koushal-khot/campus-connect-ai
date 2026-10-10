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

// Hide the year field on the register form when "Faculty" is chosen.
const roleSelect = document.getElementById("role-select");
const yearField = document.getElementById("year-field");
if (roleSelect && yearField) {
  const sync = () => (yearField.hidden = roleSelect.value !== "student");
  roleSelect.addEventListener("change", sync);
  sync();
}

// Fade flash messages after a few seconds.
document.querySelectorAll(".flash").forEach((el) =>
  setTimeout(() => el.classList.add("gone"), 4500)
);
