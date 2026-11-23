// Runs before first paint: restores light/dark without a flash and decides whether the startup intro plays.
// It plays once per launch (not on reload) and never when interface animations are off or the user turned it off in Settings.
// If Windows asks for reduced motion (its "Animation effects" switch is also off on many laptops, VMs and remote sessions) the
// intro still appears, but as a calm still splash with no movement, so the startup never just silently does nothing.
(function () {
  var root = document.documentElement;
  try { if (localStorage.getItem("panzeron-theme") === "light") root.dataset.theme = "light"; } catch (e) { /* storage unavailable */ }
  try {
    var animOff = false;
    try { animOff = JSON.parse(localStorage.getItem("panzeron-prefs") || "{}").anim === false; } catch (e) { /* ignore */ }
    var skip = sessionStorage.getItem("panzeron-booted") || localStorage.getItem("panzeron-intro") === "off" || animOff;
    if (skip) return;
    root.classList.add("booting");
    if (window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches) root.classList.add("calm");
    // Hard failsafe, independent of the app script: if that script never takes over (it failed to load or crashed) the intro
    // must not keep the interface hidden. Once the intro runs it removes "booting" itself, so this is then a no-op.
    setTimeout(function () { root.classList.remove("booting"); }, 9000);
  } catch (e) { /* storage unavailable: no intro */ }
})();
