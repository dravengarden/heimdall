(() => {
  const header = document.querySelector(".site-header");
  const menuToggle = document.querySelector("[data-menu-toggle]");
  const nav = document.querySelector("[data-site-nav]");

  if (header && menuToggle && nav) {
    const setMenuState = (open) => {
      header.classList.toggle("nav-open", open);
      menuToggle.setAttribute("aria-expanded", String(open));
      menuToggle.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
    };

    menuToggle.addEventListener("click", () => {
      setMenuState(!header.classList.contains("nav-open"));
    });

    nav.addEventListener("click", (event) => {
      if (event.target.closest("a")) setMenuState(false);
    });

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") setMenuState(false);
    });
  }

  document.querySelectorAll("[data-copy]").forEach((button) => {
    button.addEventListener("click", async () => {
      const selector = button.getAttribute("data-copy");
      const source = selector ? document.querySelector(selector) : null;
      if (!source) return;

      try {
        await navigator.clipboard.writeText(source.textContent.trim());
        const original = button.textContent;
        button.textContent = "Copied";
        window.setTimeout(() => {
          button.textContent = original;
        }, 1400);
      } catch {
        button.textContent = "Select manually";
        window.setTimeout(() => {
          button.textContent = "Copy";
        }, 1600);
      }
    });
  });

  const currentPage = document.body.dataset.page;
  if (currentPage) {
    document.querySelectorAll(`a[data-page="${currentPage}"]`).forEach((link) => {
      link.setAttribute("aria-current", "page");
    });
  }
})();
