document.addEventListener("DOMContentLoaded", function () {
  // 1. Fetch your existing versions.json from the root
  fetch('/versions.json')
    .then(response => response.json())
    .then(versions => {
      // 2. Identify the latest version from your file
      const latestObj = versions.find(v => v.aliases && v.aliases.includes('latest'));
      if (!latestObj) return;

      const latestVersion = latestObj.version;
      
      // 3. Extract the current version from the URL path (e.g., /0.1/index.html -> 0.1)
      const pathSegments = window.location.pathname.split('/').filter(Boolean);
      const currentVersion = pathSegments[0]; 

      // 4. If the user is on an older version, inject a warning banner
      if (currentVersion && currentVersion !== latestVersion && currentVersion !== 'latest') {
        const banner = document.createElement('div');
        banner.style.cssText = "background: #ffecb3; color: #5d4037; padding: 12px; text-align: center; font-weight: bold; width: 100%; position: sticky; top: 0; z-index: 999;";
        banner.innerHTML = `⚠️ You are viewing an outdated version (${currentVersion}). <a href="/latest/" style="color: #000; text-decoration: underline;">Click here to see the latest version (${latestVersion}).</a>`;
        document.body.insertBefore(banner, document.body.firstChild);
      }
    })
    .catch(err => console.error("Could not load version warning:", err));
});
